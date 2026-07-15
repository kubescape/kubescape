package printer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	gitLabSASTOutputFile = "report"

	// gitLabSASTReportVersion is the GitLab security report schema version we emit.
	// See https://gitlab.com/gitlab-org/security-products/security-report-schemas
	gitLabSASTReportVersion = "15.2.4"
	// gitLabTimeFormat is the timestamp format required by the GitLab schema (no timezone).
	gitLabTimeFormat = "2006-01-02T15:04:05"

	gitLabScannerID     = "kubescape"
	gitLabScannerName   = "Kubescape"
	gitLabScannerURL    = "https://kubescape.io"
	gitLabScannerVendor = "Kubescape"
	gitLabControlIDType = "kubescape_control_id"
)

var _ printer.IPrinter = &GitLabSASTPrinter{}

// GitLabSASTPrinter emits configuration-scan results in the GitLab SAST report format,
// so findings surface in GitLab's Security dashboard and MR approval policies rather than
// only in the test widget (as the JUnit format does). See issue #2496.
type GitLabSASTPrinter struct {
	writer *os.File
}

// gitLabSASTReport mirrors the GitLab SAST report schema. Only the fields Kubescape
// can populate are modelled; optional fields are omitted when empty.
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
}

type gitLabScannerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type gitLabLocation struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
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

func (gp *GitLabSASTPrinter) Score(score float32) {
}

func (gp *GitLabSASTPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = gitLabSASTOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != printer.JsonOutputExt {
			outputFile = outputFile + printer.JsonOutputExt
		}
	}
	gp.writer = printer.GetWriter(ctx, outputFile)
}

func (gp *GitLabSASTPrinter) PrintNextSteps() {
}

func (gp *GitLabSASTPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("failed to write results in GitLab SAST format: image scanning is not supported")
		return
	}

	if err := gp.printConfigurationScan(ctx, opaSessionObj); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in GitLab SAST format", helpers.Error(err))
		return
	}
	printer.LogOutputFile(gp.writer.Name())
}

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

	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceSource := opaSessionObj.ResourceSource[resourceID]
		relPath := resourceSource.RelativePath

		// A finding with no file path is meaningless in GitLab's Security dashboard
		if relPath == "" && basePath == "" {
			continue
		}

		effectiveBase := basePath
		if effectiveBase == "" && resourceSource.Path != "" {
			effectiveBase = resourceSource.Path
		}
		rsrcAbsPath := filepath.Join(effectiveBase, relPath)
		locationResolver, err := locationresolver.NewFixPathLocationResolver(rsrcAbsPath)
		if err != nil {
			logger.L().Warning("failed to create location resolver, GitLab SAST locations will default to line 1", helpers.Error(err))
		}

		for _, toPin := range result.AssociatedControls {
			ac := toPin
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}

			ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
			if ctl == nil {
				logger.L().Debug("control not found in summary details, skipping", helpers.String("controlID", ac.GetID()))
				continue
			}

			location := resolveFixLocation(opaSessionObj, locationResolver, &ac, resourceID)
			report.Vulnerabilities = append(report.Vulnerabilities, toGitLabVulnerability(ctl, resourceID, relPath, location))
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
func toGitLabVulnerability(ctl reportsummary.IControlSummary, resourceID, filePath string, location locationresolver.Location) gitLabVulnerability {
	controlID := ctl.GetID()
	// Kubescape severities (Critical/High/Medium/Low/Unknown) are all valid GitLab severities
	severity := apis.ControlSeverityToString(ctl.GetScoreFactor())

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
	}
}

// gitLabVulnerabilityID returns a stable, unique identifier for a finding so GitLab can
// track it across scans for triage and dismissal.
func gitLabVulnerabilityID(controlID, resourceID, filePath string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(controlID+"/"+resourceID+"/"+filePath)))
}

// kubescapeVersion returns the current build version, or "unknown" for local builds.
func kubescapeVersion() string {
	if versioncheck.BuildNumber == "" {
		return versioncheck.UnknownBuildNumber
	}
	return versioncheck.BuildNumber
}

func (gp *GitLabSASTPrinter) CloseWriter() {
	if gp.writer != nil && gp.writer != os.Stdout {
		gp.writer.Close()
	}
}
