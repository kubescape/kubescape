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
	seen := make(map[string]struct{})
	for i := range imageScanData {
		data := &imageScanData[i]
		operatingSystem := imageOperatingSystem(data)
		for _, cve := range extractCVEs(data.Matches, data.Image, nil) {
			vulnerability := toGitLabContainerVulnerability(data.Image, data.Platform, operatingSystem, cve)
			if _, duplicate := seen[vulnerability.ID]; duplicate {
				continue
			}
			seen[vulnerability.ID] = struct{}{}
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
	if data.Context.Distro == nil {
		return gitLabUnknownOperatingSystem
	}
	if name := strings.TrimSpace(data.Context.Distro.String()); name != "" {
		return name
	}
	return gitLabUnknownOperatingSystem
}

func toGitLabContainerVulnerability(image, platform, operatingSystem string, cve imageprinter.CVE) gitLabContainerVulnerability {
	severity := mapGitLabSeverity(cve.Severity)
	description := fmt.Sprintf("Package %s version %s is affected by %s (severity: %s).", cve.Package, cve.Version, cve.ID, severity)
	if platform != "" {
		description += fmt.Sprintf(" Scanned platform: %s.", platform)
	}

	vulnerability := gitLabContainerVulnerability{
		ID:          gitLabImageVulnerabilityID(image, cve.Package, cve.Version, cve.ID, platform),
		Name:        truncateRunes(fmt.Sprintf("%s in %s %s", cve.ID, cve.Package, cve.Version), gitLabMaxNameLength),
		Description: description,
		Severity:    severity,
		Identifiers: []gitLabIdentifier{gitLabAdvisoryIdentifier(cve.ID)},
		Location: gitLabContainerLocation{
			Dependency:      gitLabDependency{Package: gitLabPackage{Name: cve.Package}, Version: cve.Version},
			OperatingSystem: operatingSystem,
			Image:           image,
		},
	}
	if len(cve.FixVersions) > 0 {
		vulnerability.Solution = fmt.Sprintf("Upgrade %s to version %s.", cve.Package, strings.Join(cve.FixVersions, ", "))
	}
	return vulnerability
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
