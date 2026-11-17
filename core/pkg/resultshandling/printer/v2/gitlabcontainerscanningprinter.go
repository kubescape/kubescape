package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
)

const (
	gitLabContainerScanningOutputFile = "gl-container-scanning-report"
	gitLabUnknownOperatingSystem      = "Unknown"
	gitLabMaxNameLength               = 255
)

var _ printer.IPrinter = &GitLabContainerScanningPrinter{}

type GitLabContainerScanningPrinter struct {
	writer *os.File
}

type gitLabContainerScanningReport struct {
	Version         string                         `json:"version"`
	Scan            gitLabScan                     `json:"scan"`
	Vulnerabilities []gitLabContainerVulnerability `json:"vulnerabilities"`
}

type gitLabContainerVulnerability struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Severity    string                  `json:"severity"`
	Solution    string                  `json:"solution,omitempty"`
	Identifiers []gitLabIdentifier      `json:"identifiers"`
	Location    gitLabContainerLocation `json:"location"`
	Details     map[string]gitLabDetail `json:"details,omitempty"`
}

type gitLabContainerLocation struct {
	Dependency      gitLabDependency `json:"dependency"`
	OperatingSystem string           `json:"operating_system"`
	Image           string           `json:"image"`
}

func NewGitLabContainerScanningPrinter() *GitLabContainerScanningPrinter {
	return &GitLabContainerScanningPrinter{}
}

func (cp *GitLabContainerScanningPrinter) Score(float32) {}

func (cp *GitLabContainerScanningPrinter) PrintNextSteps() {}

func (cp *GitLabContainerScanningPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.GitLabContainerScanningFormat, outputFile, gitLabContainerScanningOutputFile)
	if explicitOutput {
		var err error
		cp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	cp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (cp *GitLabContainerScanningPrinter) ActionPrint(ctx context.Context, _ *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if len(imageScanData) == 0 {
		return fmt.Errorf("gitlab-container-scanning output requires scanned images: run %q or add --scan-images", cautils.ExecName()+" scan image")
	}

	startedAt := time.Now().UTC()
	report := gitLabContainerScanningReport{
		Version:         gitLabSASTReportVersion,
		Vulnerabilities: []gitLabContainerVulnerability{},
	}
	seen := make(map[string]int)
	fixes := make(map[string][]string)
	for i := range imageScanData {
		data := &imageScanData[i]
		image := normalizeImageRef(data.Image)
		operatingSystem := imageOperatingSystem(data)
		for _, cve := range extractCVEs(data.Matches, data.Image, nil) {
			vulnerability := toGitLabContainerVulnerability(image, data.Platform, operatingSystem, cve)
			if idx, duplicate := seen[vulnerability.ID]; duplicate {
				if len(cve.FixVersions) > 0 {
					merged := mergeFixVersions(fixes[vulnerability.ID], cve.FixVersions)
					fixes[vulnerability.ID] = merged
					report.Vulnerabilities[idx].Solution = gitLabSolution(cve.Package, merged)
				}
				continue
			}
			seen[vulnerability.ID] = len(report.Vulnerabilities)
			fixes[vulnerability.ID] = mergeFixVersions(nil, cve.FixVersions)
			vulnerability.Solution = gitLabSolution(cve.Package, fixes[vulnerability.ID])
			report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
		}
	}

	scanner := gitLabScanner{
		ID:      gitLabScannerID,
		Name:    gitLabScannerName,
		URL:     gitLabScannerURL,
		Version: kubescapeVersion(),
		Vendor:  gitLabVendor{Name: gitLabScannerVendor},
	}
	report.Scan = gitLabScan{
		Analyzer:  scanner,
		Scanner:   scanner,
		Type:      "container_scanning",
		StartTime: startedAt.Format(gitLabTimeFormat),
		EndTime:   time.Now().UTC().Format(gitLabTimeFormat),
		Status:    "success",
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_, err = cp.writer.Write(encoded)
	}
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in GitLab Container Scanning format", helpers.Error(err))
		return fmt.Errorf("failed to write results in GitLab Container Scanning format: %w", err)
	}
	printer.LogOutputFile(cp.writer.Name())
	return nil
}

func imageOperatingSystem(data *cautils.ImageScanData) string {
	osName := gitLabUnknownOperatingSystem
	if data.Context.Distro != nil {
		if name := strings.TrimSpace(data.Context.Distro.String()); name != "" {
			osName = name
		}
	}
	if data.Platform != "" {
		return fmt.Sprintf("%s (%s)", osName, data.Platform)
	}
	return osName
}

// normalizeImageRef appends the default ":latest" tag to untagged image references
// (e.g. "nginx" -> "nginx:latest", "localhost:5000/app" -> "localhost:5000/app:latest").
// This ensures GitLab's location parser identifies the image tag component and does
// not generate empty-component fingerprint collisions across untagged images.
func normalizeImageRef(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return image
	}
	ref := image
	if at := strings.Index(ref, "@"); at != -1 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if slash != -1 {
		ref = ref[slash+1:]
	}
	if !strings.Contains(ref, ":") {
		if at := strings.Index(image, "@"); at != -1 {
			return image[:at] + ":latest" + image[at:]
		}
		return image + ":latest"
	}
	return image
}

func mergeFixVersions(existing, added []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(added))
	var result []string
	for _, v := range existing {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	for _, v := range added {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func gitLabSolution(pkg string, fixVersions []string) string {
	if len(fixVersions) == 0 {
		return ""
	}
	return fmt.Sprintf("Upgrade %s to version %s.", pkg, strings.Join(fixVersions, ", "))
}

func toGitLabContainerVulnerability(image, platform, operatingSystem string, cve imageprinter.CVE) gitLabContainerVulnerability {
	severity := mapGitLabSeverity(cve.Severity)
	description := fmt.Sprintf("Package %s version %s is affected by %s (severity: %s).", cve.Package, cve.Version, cve.ID, severity)
	if platform != "" {
		description += fmt.Sprintf(" Scanned platform: %s.", platform)
	}

	return gitLabContainerVulnerability{
		ID:          gitLabImageVulnerabilityID(image, cve.Package, cve.Version, cve.ID, platform),
		Name:        truncateRunes(fmt.Sprintf("%s in %s %s", cve.ID, cve.Package, cve.Version), gitLabMaxNameLength),
		Description: description,
		Severity:    severity,
		Solution:    gitLabSolution(cve.Package, cve.FixVersions),
		Identifiers: []gitLabIdentifier{gitLabAdvisoryIdentifier(cve.ID)},
		Location: gitLabContainerLocation{
			Dependency:      gitLabDependency{Package: gitLabPackage{Name: cve.Package}, Version: cve.Version},
			OperatingSystem: operatingSystem,
			Image:           image,
		},
		Details: gitLabExploitDetails(cve),
	}
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit-1]) + "…"
}

func (cp *GitLabContainerScanningPrinter) CloseWriter() error {
	if cp.writer != nil && cp.writer != os.Stdout {
		return cp.writer.Close()
	}
	return nil
}
