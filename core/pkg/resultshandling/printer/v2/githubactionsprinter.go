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

	// githubActionsMaxSkippedControlWarnings limits skipped-control warning
	// annotations to 9, reserving 1 of the 10 per-step warning annotation slots
	// for the scan-level degraded coverage warning.
	githubActionsMaxSkippedControlWarnings = 9

	// githubActionsMaxStepSummaryBytes mirrors GitHub's 1 MiB step summary limit.
	// Summaries exceeding this limit are rejected by the GitHub Actions runner.
	githubActionsMaxStepSummaryBytes = 1024 * 1024

	// githubActionsStepSummarySafetyMargin keeps appended content clear of
	// runner edge cases near the exact 1 MiB boundary.
	githubActionsStepSummarySafetyMargin = 4 * 1024
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
	writer          *os.File
	stepSummaryPath string
}

func NewGitHubActionsPrinter() *GitHubActionsPrinter {
	return &GitHubActionsPrinter{
		stepSummaryPath: os.Getenv("GITHUB_STEP_SUMMARY"),
	}
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

	if opaSessionObj.ScanCoverage.Degraded {
		scoreStr := cautils.ComplianceScoreToString(opaSessionObj.ScanCoverage.CoverageScore, 2)
		fmt.Fprintf(gp.writer, "::warning title=Degraded Scan Coverage::Scan coverage is degraded (%s%%): %d of %d controls evaluated\n",
			scoreStr, opaSessionObj.ScanCoverage.EvaluatedControls, opaSessionObj.ScanCoverage.TotalControls)

		skippedControls := collectSkippedControls(opaSessionObj)
		emittedWarnings := 0
		for _, sc := range skippedControls {
			if emittedWarnings == githubActionsMaxSkippedControlWarnings {
				break
			}
			msg := fmt.Sprintf("Control %s was not evaluated: %s", sc.controlID, sc.reason)
			if sc.reason == "" {
				msg = fmt.Sprintf("Control %s was not evaluated", sc.controlID)
			}
			fmt.Fprintf(gp.writer, "::warning title=%s::%s\n",
				escapeAnnotationProperty("Control "+sc.controlID+" Skipped"),
				escapeAnnotationData(msg))
			emittedWarnings++
		}
		if omitted := len(skippedControls) - emittedWarnings; omitted > 0 {
			fmt.Fprintf(gp.writer, "Kubescape: %d of %d skipped control(s) annotated as warnings; %d omitted due to GitHub's 10-warning step limit. See step summary for full list.\n",
				emittedWarnings, len(skippedControls), omitted)
			logger.L().Ctx(ctx).Warning("skipped controls omitted from GitHub Actions warning annotations",
				helpers.Int("omittedControls", omitted),
				helpers.Int("totalSkippedControls", len(skippedControls)))
		}
	}

	if summaryPath := gp.stepSummaryPath; summaryPath != "" {
		if err := writeStepSummary(ctx, summaryPath, opaSessionObj); err != nil {
			logger.L().Ctx(ctx).Warning("failed to write GitHub Actions step summary", helpers.Error(err))
		}
	}

	printer.LogOutputFile(gp.writer.Name())
	return nil
}

type summarySection struct {
	header string
	rows   []string
}

func formatTruncationNotice(omittedCount int) string {
	if omittedCount == 1 {
		return "\n\n> **Note:** Summary truncated to stay within GitHub's 1 MiB limit (1 entry omitted).\n"
	}
	return fmt.Sprintf("\n\n> **Note:** Summary truncated to stay within GitHub's 1 MiB limit (%d entries omitted).\n", omittedCount)
}

func generateStepSummaryWithBudget(opaSessionObj *cautils.OPASessionObj, maxBytes int) string {
	if opaSessionObj == nil || maxBytes <= 0 {
		return ""
	}

	var base strings.Builder
	base.WriteString("### Kubescape Scan Coverage Summary\n\n")

	status := "Full Coverage"
	if opaSessionObj.ScanCoverage.Degraded {
		status = "Degraded"
	}

	base.WriteString("| Metric | Value |\n")
	base.WriteString("| --- | --- |\n")
	fmt.Fprintf(&base, "| Coverage Score | %s%% |\n", cautils.ComplianceScoreToString(opaSessionObj.ScanCoverage.CoverageScore, 2))
	fmt.Fprintf(&base, "| Status | %s |\n", status)
	fmt.Fprintf(&base, "| Evaluated Controls | %d / %d |\n", opaSessionObj.ScanCoverage.EvaluatedControls, opaSessionObj.ScanCoverage.TotalControls)
	if opaSessionObj.Report != nil &&
		opaSessionObj.ScanCoverage.EvaluatedControls > 0 &&
		opaSessionObj.Report.SummaryDetails.ComplianceScore >= 0 {
		fmt.Fprintf(&base, "| Compliance Score | %s%% |\n", cautils.ComplianceScoreToString(opaSessionObj.Report.SummaryDetails.ComplianceScore, 2))
	}

	var sections []summarySection

	skippedControls := collectSkippedControls(opaSessionObj)
	if len(skippedControls) > 0 {
		rows := make([]string, 0, len(skippedControls))
		for _, sc := range skippedControls {
			name := sc.name
			if name == "" {
				name = sc.controlID
			}
			reason := sc.reason
			if reason == "" {
				reason = "not evaluated"
			}
			rows = append(rows, fmt.Sprintf("| %s | %s | %s |\n",
				sc.controlID,
				sanitizeMarkdownTableCell(name),
				sanitizeMarkdownTableCell(reason)))
		}
		sections = append(sections, summarySection{
			header: "\n#### Skipped Controls\n\n| Control ID | Name | Reason |\n| --- | --- | --- |\n",
			rows:   rows,
		})
	}

	failedGVRs := opaSessionObj.ScanCoverage.FailedGVRPulls
	partialPulls := opaSessionObj.ScanCoverage.PartialGVRPulls
	if len(failedGVRs) > 0 || len(partialPulls) > 0 {
		rows := make([]string, 0, len(failedGVRs)+len(partialPulls))
		for _, f := range failedGVRs {
			rows = append(rows, fmt.Sprintf("| %s | %s |\n",
				sanitizeMarkdownTableCell(f.GVR),
				sanitizeMarkdownTableCell(f.Error)))
		}
		for _, p := range partialPulls {
			target := p.GVR
			if p.Selector != "" {
				target = fmt.Sprintf("%s (%s)", p.GVR, p.Selector)
			}
			rows = append(rows, fmt.Sprintf("| %s | %s |\n",
				sanitizeMarkdownTableCell(target),
				sanitizeMarkdownTableCell(p.Error)))
		}
		sections = append(sections, summarySection{
			header: "\n#### Failed Resource Queries\n\n| Resource (GVR) | Error |\n| --- | --- |\n",
			rows:   rows,
		})
	}

	if len(opaSessionObj.ScanCoverage.SkippedManifests) > 0 {
		rows := make([]string, 0, len(opaSessionObj.ScanCoverage.SkippedManifests))
		for _, sm := range opaSessionObj.ScanCoverage.SkippedManifests {
			rows = append(rows, fmt.Sprintf("| %s | %s |\n",
				sanitizeMarkdownTableCell(sm.Path),
				sanitizeMarkdownTableCell(sm.Reason)))
		}
		sections = append(sections, summarySection{
			header: "\n#### Skipped Manifests\n\n| File | Reason |\n| --- | --- |\n",
			rows:   rows,
		})
	}

	if len(opaSessionObj.ScanCoverage.PolicyDegradations) > 0 {
		rows := make([]string, 0, len(opaSessionObj.ScanCoverage.PolicyDegradations))
		for _, pd := range opaSessionObj.ScanCoverage.PolicyDegradations {
			rows = append(rows, fmt.Sprintf("| %s | %s |\n",
				sanitizeMarkdownTableCell(pd.Component),
				sanitizeMarkdownTableCell(pd.Reason)))
		}
		sections = append(sections, summarySection{
			header: "\n#### Policy Degradations\n\n| Component | Reason |\n| --- | --- |\n",
			rows:   rows,
		})
	}

	totalEntries := 0
	for _, sec := range sections {
		totalEntries += len(sec.rows)
	}

	if totalEntries == 0 {
		if base.Len() <= maxBytes {
			return base.String()
		}
		return ""
	}

	// Fast path: if the entire summary fits within maxBytes, return it un-truncated.
	totalFullLen := base.Len()
	for _, sec := range sections {
		totalFullLen += len(sec.header)
		for _, r := range sec.rows {
			totalFullLen += len(r)
		}
	}
	if totalFullLen <= maxBytes {
		var sb strings.Builder
		sb.WriteString(base.String())
		for _, sec := range sections {
			sb.WriteString(sec.header)
			for _, r := range sec.rows {
				sb.WriteString(r)
			}
		}
		return sb.String()
	}

	// Truncation required.
	if base.Len()+len(formatTruncationNotice(totalEntries)) > maxBytes {
		notice := formatTruncationNotice(totalEntries)
		if len(notice) <= maxBytes {
			return notice
		}
		return ""
	}

	var sb strings.Builder
	sb.WriteString(base.String())

	emittedEntries := 0
outerLoop:
	for _, sec := range sections {
		if len(sec.rows) == 0 {
			continue
		}

		noticeLenForFirst := 0
		if rem := totalEntries - (emittedEntries + 1); rem > 0 {
			noticeLenForFirst = len(formatTruncationNotice(rem))
		}
		neededForFirst := len(sec.header) + len(sec.rows[0]) + noticeLenForFirst
		if sb.Len()+neededForFirst > maxBytes {
			break outerLoop
		}

		sb.WriteString(sec.header)
		sb.WriteString(sec.rows[0])
		emittedEntries++

		for _, row := range sec.rows[1:] {
			noticeLen := 0
			if rem := totalEntries - (emittedEntries + 1); rem > 0 {
				noticeLen = len(formatTruncationNotice(rem))
			}
			needed := len(row) + noticeLen
			if sb.Len()+needed > maxBytes {
				break outerLoop
			}
			sb.WriteString(row)
			emittedEntries++
		}
	}

	omitted := totalEntries - emittedEntries
	if omitted > 0 {
		sb.WriteString(formatTruncationNotice(omitted))
	}

	return sb.String()
}

func sanitizeMarkdownTableCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func writeStepSummary(ctx context.Context, summaryPath string, opaSessionObj *cautils.OPASessionObj) error {
	if summaryPath == "" || opaSessionObj == nil {
		return nil
	}

	cleanPath := filepath.Clean(summaryPath)
	var existingSize int64
	if stat, err := os.Stat(cleanPath); err == nil {
		existingSize = stat.Size()
	}

	if existingSize >= githubActionsMaxStepSummaryBytes {
		logger.L().Ctx(ctx).Warning("GitHub Actions step summary limit reached by existing content, skipping append",
			helpers.Int("existingSize", int(existingSize)),
			helpers.Int("maxBytes", githubActionsMaxStepSummaryBytes))
		return nil
	}

	remainingBytes := int(githubActionsMaxStepSummaryBytes - githubActionsStepSummarySafetyMargin - existingSize)
	if remainingBytes <= 0 {
		logger.L().Ctx(ctx).Warning("GitHub Actions step summary remaining capacity within safety margin, skipping append",
			helpers.Int("existingSize", int(existingSize)),
			helpers.Int("maxBytes", githubActionsMaxStepSummaryBytes),
			helpers.Int("safetyMarginBytes", githubActionsStepSummarySafetyMargin))
		return nil
	}
	content := generateStepSummaryWithBudget(opaSessionObj, remainingBytes)
	if content == "" {
		logger.L().Ctx(ctx).Warning("GitHub Actions step summary content could not fit within remaining budget, skipping append",
			helpers.Int("remainingBytes", remainingBytes))
		return nil
	}

	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G703, G304 -- summaryPath is passed from GitHub runner environment variable
	if err != nil {
		return fmt.Errorf("failed to open step summary file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to step summary file: %w", err)
	}
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
			if !cautils.ControlStatus(&opaSessionObj.Report.SummaryDetails, &ac).IsFailed() {
				continue
			}
			ac = cautils.FailedRules(&opaSessionObj.Report.SummaryDetails, ac)

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
			if res, ok := opaSessionObj.GetResource(resource.resourceID); ok && res != nil {
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
