package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	githubActionsOutputFile = "github-actions"

	// githubActionsMaxAnnotations mirrors the GitHub Actions runner's per-step
	// cap: at most 10 error annotations are rendered per step and the rest are
	// silently dropped, so emitting more would lose findings invisibly.
	githubActionsMaxAnnotations = 10
)

var _ printer.IPrinter = &GitHubActionsPrinter{}

// GitHubActionsPrinter emits failed High and Critical controls as GitHub
// Actions workflow commands (::error file=...,line=...::message), which the
// runner renders as inline annotations on the pull request. Unlike SARIF
// code-scanning, annotations require no GitHub Advanced Security license and
// work on private repositories. Findings without a repository-relative
// manifest path cannot be anchored to a PR line and are skipped with a
// warning, following the same rules as the GitLab SAST printer.
type GitHubActionsPrinter struct {
	writer *os.File
}

func NewGitHubActionsPrinter() *GitHubActionsPrinter {
	return &GitHubActionsPrinter{}
}

// Score is a no-op: workflow commands carry no aggregate score.
func (gp *GitHubActionsPrinter) Score(float32) {}

// PrintNextSteps is a no-op: annotations are consumed by the Actions runner,
// not read by a human at the terminal.
func (gp *GitHubActionsPrinter) PrintNextSteps() {}

// SetWriter defaults to stdout — the Actions runner parses workflow commands
// from the step's log, so writing there is what makes annotations zero-config
// — and honors an explicit --output path for users who want to cat the file in
// a later step.
func (gp *GitHubActionsPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.GitHubActionsFormat, outputFile, githubActionsOutputFile)
	if explicitOutput {
		var err error
		gp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	gp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

// ActionPrint writes failed High/Critical controls as workflow commands. Only
// configuration scans are supported: image findings have no manifest location
// to anchor an annotation to.
func (gp *GitHubActionsPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		return fmt.Errorf("github-actions output is only supported for configuration scanning: image findings have no manifest location to annotate")
	}

	annotations, belowThreshold := gp.collectAnnotations(ctx, opaSessionObj)

	// Critical before High, then stable ControlID/ResourceID order, so the
	// ten most severe findings are the ones that survive the runner's cap.
	sort.SliceStable(annotations, func(i, j int) bool {
		if annotations[i].severityRank != annotations[j].severityRank {
			return annotations[i].severityRank > annotations[j].severityRank
		}
		if annotations[i].controlID != annotations[j].controlID {
			return annotations[i].controlID < annotations[j].controlID
		}
		return annotations[i].resourceID < annotations[j].resourceID
	})

	emitted := 0
	for _, annotation := range annotations {
		if emitted == githubActionsMaxAnnotations {
			break
		}
		fmt.Fprintf(gp.writer, "::error file=%s,line=%d,title=%s::%s\n",
			escapeAnnotationProperty(annotation.file),
			annotation.line,
			escapeAnnotationProperty(annotation.title),
			escapeAnnotationData(annotation.message))
		emitted++
	}

	fmt.Fprintf(gp.writer, "Kubescape: %d of %d High/Critical finding(s) annotated; %d suppressed by GitHub's 10-annotation step limit; %d finding(s) below the High severity threshold. Use --format json for the complete report.\n",
		emitted, len(annotations), len(annotations)-emitted, belowThreshold)

	printer.LogOutputFile(gp.writer.Name())
	return nil
}

// ghAnnotation is one candidate workflow command before the per-step cap.
type ghAnnotation struct {
	severityRank int
	severity     string
	controlID    string
	resourceID   string
	file         string
	line         int
	title        string
	message      string
}

// collectAnnotations resolves every failed High/Critical control on every
// failed resource into one annotation candidate, following the same
// file-location rules as the GitLab SAST printer: findings without a
// repository-relative manifest path cannot be anchored to a PR line and are
// skipped with a warning. belowThreshold counts failed findings at severities
// the format deliberately does not annotate.
func (gp *GitHubActionsPrinter) collectAnnotations(ctx context.Context, opaSessionObj *cautils.OPASessionObj) (annotations []ghAnnotation, belowThreshold int) {
	basePath := getBasePathFromMetadata(*opaSessionObj)

	var withoutFilePath, outsideRepository int
	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
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
			relPath:    relPath,
			absPath:    filepath.Join(effectiveBasePath(resourceSource, basePath), relPath),
		})
	}

	// The same skipped-resource warnings the GitLab SAST printer emits, so both
	// location-anchoring formats explain exclusions identically.
	if outsideRepository > 0 {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitHub Actions annotations because their paths are outside the repository root; scan a path inside the repository to include them",
			helpers.Int("excludedResources", outsideRepository))
	}
	if withoutFilePath > 0 && basePath != "" {
		logger.L().Ctx(ctx).Warning("some failed resources were excluded from the GitHub Actions annotations because they are not associated with a file",
			helpers.Int("excludedResources", withoutFilePath))
	}

	var caches manifestCache
	for _, resource := range groupByManifest(failed) {
		locationResolver := caches.get(resource.absPath).locationResolver(resource.absPath, "GitHub Actions")

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

			severityRank := apis.ControlSeverityToInt(ctl.GetScoreFactor())
			if severityRank < apis.SeverityHigh {
				belowThreshold++
				continue
			}

			location := resolveFixLocation(opaSessionObj, locationResolver, &ac, resource.resourceID)
			msg := fmt.Sprintf("%s severity finding on %s. Remediation: %s",
				apis.ControlSeverityToString(ctl.GetScoreFactor()), resource.resourceID, cautils.GetControlLink(ctl.GetID()))
			if res, ok := opaSessionObj.AllResources[resource.resourceID]; ok {
				if paths := AssistedRemediationPathsWithCurrentValuesFiltered(&ac, res, false); len(paths) > 0 {
					msg += "\nFailed paths:\n" + strings.Join(paths, "\n")
				}
			}
			annotations = append(annotations, ghAnnotation{
				severityRank: severityRank,
				severity:     apis.ControlSeverityToString(ctl.GetScoreFactor()),
				controlID:    ctl.GetID(),
				resourceID:   resource.resourceID,
				file:         resource.relPath,
				line:         location.Line,
				title:        fmt.Sprintf("%s %s", ctl.GetID(), ctl.GetName()),
				message:      msg,
			})
		}
	}

	return annotations, belowThreshold
}

// escapeAnnotationData escapes the message portion of a workflow command,
// where only %, CR and LF break the command syntax.
func escapeAnnotationData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeAnnotationProperty escapes a workflow-command property value, which in
// addition to the data escapes must mask ',' and ':' — the property
// delimiters.
func escapeAnnotationProperty(s string) string {
	s = escapeAnnotationData(s)
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// CloseWriter closes the annotations output writer, returning any error from
// flushing or closing.
func (gp *GitHubActionsPrinter) CloseWriter() error {
	if gp.writer != nil && gp.writer != os.Stdout {
		return gp.writer.Close()
	}
	return nil
}
