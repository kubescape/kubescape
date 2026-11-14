package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	gitLabCodeQualityOutputFile = "gl-code-quality-report"
	gitLabCodeQualityEngine     = "kubescape"
	gitLabCodeQualityCategory   = "Security"
	gitLabCodeQualityIssueType  = "issue"
)

var _ printer.IPrinter = &GitLabCodeQualityPrinter{}

// GitLabCodeQualityPrinter writes failed controls as a GitLab Code Quality
// report, the CodeClimate subset GitLab renders in the merge request widget
// and diff view on every tier.
type GitLabCodeQualityPrinter struct {
	writer      *os.File
	showSecrets bool
}

type codeQualityIssue struct {
	Type        string              `json:"type"`
	CheckName   string              `json:"check_name"`
	Description string              `json:"description"`
	Content     codeQualityContent  `json:"content"`
	Categories  []string            `json:"categories"`
	Severity    string              `json:"severity"`
	Fingerprint string              `json:"fingerprint"`
	EngineName  string              `json:"engine_name"`
	Location    codeQualityLocation `json:"location"`
}

type codeQualityContent struct {
	Body string `json:"body"`
}

type codeQualityLocation struct {
	Path  string           `json:"path"`
	Lines codeQualityLines `json:"lines"`
}

type codeQualityLines struct {
	Begin int `json:"begin"`
}

func NewGitLabCodeQualityPrinter(showSecrets bool) *GitLabCodeQualityPrinter {
	return &GitLabCodeQualityPrinter{showSecrets: showSecrets}
}

func (cp *GitLabCodeQualityPrinter) Score(float32) {}

func (cp *GitLabCodeQualityPrinter) PrintNextSteps() {}

func (cp *GitLabCodeQualityPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.GitLabCodeQualityFormat, outputFile, gitLabCodeQualityOutputFile)
	if explicitOutput {
		var err error
		cp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	cp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (cp *GitLabCodeQualityPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		return fmt.Errorf("gitlab-codequality output is only supported for configuration scanning: image findings have no repository file to anchor to")
	}
	if len(imageScanData) > 0 {
		return fmt.Errorf("gitlab-codequality cannot carry image vulnerabilities; use json or sarif for a combined scan with --scan-images")
	}

	encoded, err := json.MarshalIndent(cp.collectIssues(ctx, opaSessionObj), "", "  ")
	if err == nil {
		_, err = cp.writer.Write(encoded)
	}
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in GitLab Code Quality format", helpers.Error(err))
		return fmt.Errorf("failed to write results in GitLab Code Quality format: %w", err)
	}
	printer.LogOutputFile(cp.writer.Name())
	return nil
}

func (cp *GitLabCodeQualityPrinter) collectIssues(ctx context.Context, opaSessionObj *cautils.OPASessionObj) []codeQualityIssue {
	issues := []codeQualityIssue{}
	basePath := getBasePathFromMetadata(opaSessionObj)

	var withoutFilePath, outsideRepository int
	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !cautils.ResourceStatus(&opaSessionObj.Report.SummaryDetails, &result).IsFailed() {
			continue
		}

		resourceSource := opaSessionObj.ResourceSource[resourceID]
		relPath := resourceSource.RelativePath
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
			relPath:    filepath.ToSlash(relPath),
			absPath:    filepath.Join(effectiveBasePath(resourceSource, basePath), relPath),
		})
	}

	var caches manifestCache
	for _, resource := range groupByManifest(failed) {
		locationResolver := caches.get(resource.absPath).locationResolver(resource.absPath, "GitLab Code Quality")
		res, _ := opaSessionObj.GetResource(resource.resourceID)

		for _, toPin := range opaSessionObj.ResourcesResult[resource.resourceID].AssociatedControls {
			ac := toPin
			if !cautils.ControlStatus(&opaSessionObj.Report.SummaryDetails, &ac).IsFailed() {
				continue
			}

			ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
			if ctl == nil {
				logger.L().Debug("control not found in summary details, skipping", helpers.String("controlID", ac.GetID()))
				continue
			}

			evidence := cautils.EvidenceControl(&opaSessionObj.Report.SummaryDetails, ac)
			line := codeQualityLine(opaSessionObj, locationResolver, &evidence, resource.resourceID)
			issues = append(issues, toCodeQualityIssue(ctl, &evidence, res, resource.resourceID, resource.relPath, line, cp.showSecrets))
		}
	}

	if outsideRepository > 0 {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitLab Code Quality report because their paths are outside the repository root; scan a path inside the repository to include them",
			helpers.Int("excludedResources", outsideRepository), helpers.Int("reportedIssues", len(issues)))
	}
	if withoutFilePath > 0 && basePath != "" {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitLab Code Quality report because they are not associated with a file",
			helpers.Int("excludedResources", withoutFilePath), helpers.Int("reportedIssues", len(issues)))
	}

	return issues
}

func toCodeQualityIssue(ctl reportsummary.IControlSummary, ac *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, resourceID, filePath string, line int, showSecrets bool) codeQualityIssue {
	controlID := ctl.GetID()
	description := fmt.Sprintf("%s %s", controlID, ctl.GetName())
	if resource != nil {
		description += fmt.Sprintf(" (%s/%s)", resource.GetKind(), resource.GetName())
	}

	return codeQualityIssue{
		Type:        gitLabCodeQualityIssueType,
		CheckName:   controlID,
		Description: description,
		Content:     codeQualityContent{Body: codeQualityBody(ctl, ac, resource, showSecrets)},
		Categories:  []string{gitLabCodeQualityCategory},
		Severity:    codeQualitySeverity(ctl.GetScoreFactor()),
		Fingerprint: gitLabVulnerabilityID(controlID, resourceID, filePath),
		EngineName:  gitLabCodeQualityEngine,
		Location: codeQualityLocation{
			Path:  filePath,
			Lines: codeQualityLines{Begin: line},
		},
	}
}

func codeQualityLine(opaSessionObj *cautils.OPASessionObj, resolver *locationresolver.PathLocationResolver, ac *resourcesresults.ResourceAssociatedControl, resourceID string) int {
	if location, ok := lookupFixLocation(opaSessionObj, resolver, ac, resourceID); ok {
		return location.Line
	}
	if resolver == nil {
		return 1
	}
	if docIndex, ok := getDocIndex(opaSessionObj, resourceID); ok {
		if location, _ := resolver.ResolveLocation("kind", docIndex); location.Line > 0 {
			return location.Line
		}
	}
	return 1
}

func codeQualityBody(ctl reportsummary.IControlSummary, ac *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, showSecrets bool) string {
	var sections []string
	if d := strings.TrimSpace(ctl.GetDescription()); d != "" {
		sections = append(sections, d)
	}
	if r := strings.TrimSpace(ctl.GetRemediation()); r != "" {
		sections = append(sections, "**Remediation:** "+r)
	}
	if resource != nil {
		if paths := AssistedRemediationPathsWithCurrentValuesFiltered(ac, resource, showSecrets); len(paths) > 0 {
			sections = append(sections, "**Failed paths:**\n\n- `"+strings.Join(paths, "`\n- `")+"`")
		}
	}
	sections = append(sections, fmt.Sprintf("[%s documentation](%s)", ctl.GetID(), cautils.GetControlLink(ctl.GetID())))
	return strings.Join(sections, "\n\n")
}

func codeQualitySeverity(scoreFactor float32) string {
	switch apis.ControlSeverityToInt(scoreFactor) {
	case apis.SeverityCritical:
		return "critical"
	case apis.SeverityHigh:
		return "major"
	case apis.SeverityMedium:
		return "minor"
	default:
		return "info"
	}
}

func (cp *GitLabCodeQualityPrinter) CloseWriter() error {
	if cp.writer != nil && cp.writer != os.Stdout {
		return cp.writer.Close()
	}
	return nil
}
