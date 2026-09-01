package printer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	gitLabSASTOutputFile = "report"

	// gitLabSASTReportVersion is the schema version we emit: https://gitlab.com/gitlab-org/security-products/security-report-schemas
	gitLabSASTReportVersion = "15.2.4"
	// gitLabTimeFormat is the timestamp format required by the GitLab schema (no timezone)
	gitLabTimeFormat = "2006-01-02T15:04:05"

	gitLabScannerID     = "kubescape"
	gitLabScannerName   = "Kubescape"
	gitLabScannerURL    = "https://kubescape.io"
	gitLabScannerVendor = "Kubescape"
	gitLabControlIDType = "kubescape_control_id"
	// gitLabCVEIDType is the GitLab identifier type for CVE-based image scan findings (#2782)
	gitLabCVEIDType = "cve"
)

var _ printer.IPrinter = &GitLabSASTPrinter{}

// GitLabSASTPrinter emits configuration-scan results as a GitLab SAST report, so findings reach the Security dashboard and MR approval policies rather than the test widget (#2496).
// It also emits image-scan CVEs as a GitLab Dependency Scanning report, which uses the same top-level schema (#2782).
type GitLabSASTPrinter struct {
	writer *os.File
}

// gitLabSASTReport mirrors the GitLab SAST report schema; only the fields Kubescape can populate are modelled
type gitLabSASTReport struct {
	Version         string                `json:"version"`
	Scan            gitLabScan            `json:"scan"`
	Vulnerabilities []gitLabVulnerability `json:"vulnerabilities"`
}

type gitLabScan struct {
	Analyzer  gitLabScanner `json:"analyzer"`
	Scanner   gitLabScanner `json:"scanner"`
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

type gitLabScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	URL     string       `json:"url,omitempty"`
	Version string       `json:"version"`
	Vendor  gitLabVendor `json:"vendor"`
}

type gitLabVendor struct {
	Name string `json:"name"`
}

type gitLabVulnerability struct {
	ID          string             `json:"id"`
	Category    string             `json:"category,omitempty"`
	Name        string             `json:"name,omitempty"`
	Message     string             `json:"message,omitempty"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Scanner     gitLabScannerRef   `json:"scanner"`
	Location    gitLabLocation     `json:"location"`
	Identifiers []gitLabIdentifier `json:"identifiers"`
	Solution    string             `json:"solution,omitempty"`
}

type gitLabScannerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type gitLabLocation struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	// Dependency is set alongside File for image-scan (dependency_scanning) findings. GitLab's
	// schema requires both location.file and location.dependency.version — there's no source
	// file for a container image, so File carries the image reference instead (#2782 review).
	Dependency *gitLabDependency `json:"dependency,omitempty"`
}

// gitLabDependency identifies the vulnerable package for a dependency_scanning finding
type gitLabDependency struct {
	Package gitLabPackage `json:"package"`
	Version string        `json:"version"`
}

type gitLabPackage struct {
	Name string `json:"name"`
}

type gitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// NewGitLabSASTPrinter returns a new GitLab SAST printer instance
func NewGitLabSASTPrinter() *GitLabSASTPrinter {
	return &GitLabSASTPrinter{}
}

// Score is a no-op: the GitLab SAST report has no field for the overall risk score
func (gp *GitLabSASTPrinter) Score(score float32) {
}

// SetWriter opens outputFile for writing, defaulting the name and forcing a .json extension
func (gp *GitLabSASTPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.GitLabSASTFormat, outputFile, gitLabSASTOutputFile)
	if explicitOutput {
		var err error
		gp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	gp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

// PrintNextSteps is a no-op: machine-readable output carries no human-facing guidance
func (gp *GitLabSASTPrinter) PrintNextSteps() {
}

// ActionPrint writes a GitLab SAST report for a configuration scan, or a GitLab Dependency Scanning
// report for an image scan (#2782)
func (gp *GitLabSASTPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		if len(imageScanData) == 0 {
			return fmt.Errorf("failed to write results in GitLab dependency scanning format: no data provided")
		}
		if err := gp.printImageScan(imageScanData); err != nil {
			logger.L().Ctx(ctx).Error("failed to write results in GitLab dependency scanning format", helpers.Error(err))
			return fmt.Errorf("failed to write results in GitLab dependency scanning format: %w", err)
		}
		printer.LogOutputFile(gp.writer.Name())
		return nil
	}

	if err := gp.printConfigurationScan(ctx, opaSessionObj); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in GitLab SAST format", helpers.Error(err))
		return fmt.Errorf("failed to write results in GitLab SAST format: %w", err)
	}
	printer.LogOutputFile(gp.writer.Name())
	return nil
}

// printImageScan maps each CVE found in an image scan to a GitLab Dependency Scanning vulnerability and writes the report
func (gp *GitLabSASTPrinter) printImageScan(imageScanData []cautils.ImageScanData) error {
	startedAt := time.Now().UTC()

	report := gitLabSASTReport{
		Version:         gitLabSASTReportVersion,
		Vulnerabilities: []gitLabVulnerability{},
	}

	for _, data := range imageScanData {
		cves := extractCVEs(data.Matches, data.Image, nil)
		for _, cve := range cves {
			report.Vulnerabilities = append(report.Vulnerabilities, toGitLabImageVulnerability(data.Image, data.Platform, cve))
		}
	}

	finishedAt := time.Now().UTC()
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
		Type:      "dependency_scanning",
		StartTime: startedAt.Format(gitLabTimeFormat),
		EndTime:   finishedAt.Format(gitLabTimeFormat),
		Status:    "success",
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode GitLab dependency scanning report: %w", err)
	}
	if _, err := gp.writer.Write(encoded); err != nil {
		return fmt.Errorf("failed to write GitLab dependency scanning report: %w", err)
	}
	return nil
}

// mapGitLabSeverity maps a Grype severity to one of the values the GitLab dependency_scanning
// schema allows (Info/Unknown/Low/Medium/High/Critical). Grype can return Negligible, which
// isn't in that list — passed through unmapped, one Negligible CVE invalidates the entire
// report (#2782 review).
func mapGitLabSeverity(severity string) string {
	switch severity {
	case apis.SeverityCriticalString:
		return "Critical"
	case apis.SeverityHighString:
		return "High"
	case apis.SeverityMediumString:
		return "Medium"
	case apis.SeverityLowString:
		return "Low"
	case apis.SeverityNegligibleString:
		return "Info"
	default:
		return "Unknown"
	}
}

// toGitLabImageVulnerability maps a CVE found in an image to a GitLab Dependency Scanning vulnerability
func toGitLabImageVulnerability(image, platform string, cve imageprinter.CVE) gitLabVulnerability {
	message := fmt.Sprintf("%s in %s %s", cve.ID, cve.Package, cve.Version)

	description := fmt.Sprintf("Package %s version %s is affected by %s (severity: %s).", cve.Package, cve.Version, cve.ID, cve.Severity)
	if platform != "" {
		description += fmt.Sprintf(" Scanned platform: %s.", platform)
	}
	if len(cve.FixVersions) > 0 {
		description += fmt.Sprintf(" Fix available in version(s): %s.", strings.Join(cve.FixVersions, ", "))
	} else {
		description += " No fix is currently available."
	}

	return gitLabVulnerability{
		ID:          gitLabImageVulnerabilityID(image, cve.Package, cve.Version, cve.ID, platform),
		Category:    "dependency_scanning",
		Name:        message,
		Message:     message,
		Description: description,
		Severity:    mapGitLabSeverity(cve.Severity),
		Scanner:     gitLabScannerRef{ID: gitLabScannerID, Name: gitLabScannerName},
		Location: gitLabLocation{
			File: image,
			Dependency: &gitLabDependency{
				Package: gitLabPackage{Name: cve.Package},
				Version: cve.Version,
			},
		},
		Identifiers: []gitLabIdentifier{
			{
				Type:  gitLabCVEIDType,
				Name:  cve.ID,
				Value: cve.ID,
				URL:   fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
			},
		},
	}
}

// gitLabImageVulnerabilityID returns a stable id so GitLab can track a CVE finding across scans for triage and dismissal.
// The platform is part of that identity: one image reference can be scanned for several platforms, and a finding
// dismissed on one is not thereby dismissed on another. It is appended only when a platform was requested, so ids
// for scans that do not pass --platform stay as they were.
func gitLabImageVulnerabilityID(image, pkg, version, cveID, platform string) string {
	id := image + "/" + pkg + "/" + version + "/" + cveID
	if platform != "" {
		id += "/" + platform
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(id)))
}

// printConfigurationScan maps each failed control on each failed resource to a GitLab SAST vulnerability and writes the report
func (gp *GitLabSASTPrinter) printConfigurationScan(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error {
	startedAt := opaSessionObj.Report.ReportGenerationTime
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	report := gitLabSASTReport{
		Version:         gitLabSASTReportVersion,
		Vulnerabilities: []gitLabVulnerability{},
	}

	basePath := getBasePathFromMetadata(*opaSessionObj)

	var withoutFilePath, outsideRepository int
	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceSource := opaSessionObj.ResourceSource[resourceID]
		relPath := resourceSource.RelativePath

		// location.file is built from the relative path alone, and GitLab can only anchor a finding to a file inside the repository
		if relPath == "" {
			withoutFilePath++
			logger.L().Debug("resource has no file path, skipping", helpers.String("resourceID", resourceID))
			continue
		}
		if !isRepositoryRelative(relPath) {
			outsideRepository++
			logger.L().Debug("resource path is not repository-relative, skipping", helpers.String("path", relPath), helpers.String("resourceID", resourceID))
			continue
		}

		failed = append(failed, scannedResource{
			resourceID: resourceID,
			relPath:    relPath,
			absPath:    filepath.Join(effectiveBasePath(resourceSource, basePath), relPath),
		})
	}

	var caches manifestCache
	for _, resource := range groupByManifest(failed) {
		locationResolver := caches.get(resource.absPath).locationResolver(resource.absPath, "GitLab SAST")

		for _, toPin := range opaSessionObj.ResourcesResult[resource.resourceID].AssociatedControls {
			ac := toPin
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}

			ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
			if ctl == nil {
				logger.L().Debug("control not found in summary details, skipping", helpers.String("controlID", ac.GetID()))
				continue
			}

			location := resolveFixLocation(opaSessionObj, locationResolver, &ac, resource.resourceID)
			res := opaSessionObj.AllResources[resource.resourceID]
			report.Vulnerabilities = append(report.Vulnerabilities, toGitLabVulnerability(ctl, &ac, res, resource.resourceID, resource.relPath, location))
		}
	}

	// an empty report is otherwise indistinguishable from a clean scan, so say how
	// many failed resources were dropped and why
	if outsideRepository > 0 {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitLab SAST report because their paths are outside the repository root; scan a path inside the repository to include them",
			helpers.Int("excludedResources", outsideRepository), helpers.Int("reportedVulnerabilities", len(report.Vulnerabilities)))
	}
	// a cluster scan has no file paths at all, so the exclusion is inherent to the
	// format rather than a path problem the user can act on
	if withoutFilePath > 0 && basePath != "" {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitLab SAST report because they are not associated with a file",
			helpers.Int("excludedResources", withoutFilePath), helpers.Int("reportedVulnerabilities", len(report.Vulnerabilities)))
	}

	finishedAt := time.Now().UTC()
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
		Type:      "sast",
		StartTime: startedAt.Format(gitLabTimeFormat),
		EndTime:   finishedAt.Format(gitLabTimeFormat),
		Status:    "success",
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode GitLab SAST report: %w", err)
	}
	if _, err := gp.writer.Write(encoded); err != nil {
		return fmt.Errorf("failed to write GitLab SAST report: %w", err)
	}
	return nil
}

// toGitLabVulnerability maps a failed control on a resource to a GitLab SAST vulnerability.
// ac and resource are used to populate the Solution field with fix paths and current field values,
// matching what the pretty-printer and HTML printer already emit.
func toGitLabVulnerability(ctl reportsummary.IControlSummary, ac *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, resourceID, filePath string, location locationresolver.Location) gitLabVulnerability {
	controlID := ctl.GetID()
	// Kubescape severities (Critical/High/Medium/Low/Unknown) are all valid GitLab severities
	severity := apis.ControlSeverityToString(ctl.GetScoreFactor())

	var solution string
	if resource != nil {
		if paths := AssistedRemediationPathsWithCurrentValues(ac, resource); len(paths) > 0 {
			solution = strings.Join(paths, "\n")
		}
	}

	return gitLabVulnerability{
		ID:       gitLabVulnerabilityID(controlID, resourceID, filePath),
		Category: "sast",
		// The control ID is prefixed so the finding is identifiable from GitLab's title alone
		Name:        fmt.Sprintf("%s - %s", controlID, ctl.GetName()),
		Message:     ctl.GetName(),
		Description: ctl.GetDescription(),
		Severity:    severity,
		Scanner:     gitLabScannerRef{ID: gitLabScannerID, Name: gitLabScannerName},
		Location: gitLabLocation{
			File:      filePath,
			StartLine: location.Line,
		},
		Identifiers: []gitLabIdentifier{
			{
				Type:  gitLabControlIDType,
				Name:  controlID,
				Value: controlID,
				URL:   cautils.GetControlLink(controlID),
			},
		},
		Solution: solution,
	}
}

// isRepositoryRelative reports whether p is a repository-relative file path, i.e. not empty, absolute, or escaping the repository root via ".."
func isRepositoryRelative(p string) bool {
	// GitLab resolves these paths against a repository tree using POSIX
	// semantics, so what counts as absolute must not depend on the host that
	// produced the report. filepath.IsAbs alone is host-dependent: on Windows
	// it reports false for "/etc/x", because it wants a drive letter or a UNC
	// prefix, and such a path would then be emitted as if it were relative.
	slashed := filepath.ToSlash(p)
	if p == "" || filepath.IsAbs(p) || path.IsAbs(slashed) {
		return false
	}
	cleaned := path.Clean(slashed)
	return cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

// gitLabVulnerabilityID returns a stable id so GitLab can track a finding across scans for triage and dismissal
func gitLabVulnerabilityID(controlID, resourceID, filePath string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(controlID+"/"+resourceID+"/"+filePath)))
}

// kubescapeVersion returns the current build version, or "unknown" for local builds
func kubescapeVersion() string {
	if versioncheck.BuildNumber == "" {
		return versioncheck.UnknownBuildNumber
	}
	return versioncheck.BuildNumber
}

// CloseWriter closes the GitLab SAST output writer, returning any error from flushing or closing.
func (gp *GitLabSASTPrinter) CloseWriter() error {
	if gp.writer != nil && gp.writer != os.Stdout {
		return gp.writer.Close()
	}
	return nil
}
