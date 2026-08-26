package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	tableutils "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	markdownOutputFile  = "report"
	markdownTempPattern = "kubescape-md-*.md"
)

var _ printer.IPrinter = &MarkdownPrinter{}

type MarkdownPrinter struct {
	writer *os.File
}

func NewMarkdownPrinter() *MarkdownPrinter {
	return &MarkdownPrinter{}
}

func (mp *MarkdownPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.MarkdownFormat, outputFile, markdownOutputFile)
	if !explicitOutput {
		outputFile = printer.ResolveDefaultOutputFile(printer.MarkdownFormat, markdownOutputFile)
		logger.L().Info("no --output specified for markdown format; writing to default file",
			helpers.String("filename", outputFile))
	}
	if explicitOutput {
		var err error
		mp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	mp.writer = printer.GetWriterNoStdoutFallback(ctx, outputFile, markdownTempPattern)
	return nil
}

func (mp *MarkdownPrinter) Score(score float32) {
}

func (mp *MarkdownPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil && len(imageScanData) > 0 {
		if err := mdWriteImageScanReport(mp.writer, imageScanData); err != nil {
			return err
		}
		printer.LogOutputFile(mp.writer.Name())
		return nil
	}

	if opaSessionObj == nil || opaSessionObj.Report == nil {
		logger.L().Ctx(ctx).Error("no data provided for markdown output")
		return nil
	}

	summaryDetails := &opaSessionObj.Report.SummaryDetails
	w := mp.writer

	ew := &mdErrWriter{w: w}
	ew.printf("# Kubescape Security Report\n\n")
	if score := cautils.ComplianceScoreToInt(summaryDetails.ComplianceScore); score < 0 {
		ew.printf("**Compliance Score:** N/A\n\n")
	} else {
		ew.printf("**Compliance Score:** %d%%\n\n", score)
	}
	if ew.err != nil {
		return ew.err
	}

	sorted := mdSortedControls(summaryDetails.Controls)

	if err := mdWriteSummaryTable(w, sorted); err != nil {
		return err
	}
	if err := mdWriteFailedSection(ctx, w, sorted, opaSessionObj); err != nil {
		return err
	}

	printer.LogOutputFile(w.Name())
	return nil
}

func (mp *MarkdownPrinter) PrintNextSteps() {}

// CloseWriter closes the Markdown output writer, returning any error from flushing or closing.
func (mp *MarkdownPrinter) CloseWriter() error {
	if mp.writer != nil && mp.writer != os.Stdout {
		return mp.writer.Close()
	}
	return nil
}

// mdErrWriter wraps an io.Writer and records the first write error so callers
// can issue multiple printf calls and check once at the end.
type mdErrWriter struct {
	w   io.Writer
	err error
}

func (e *mdErrWriter) printf(format string, args ...interface{}) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func mdSortedControls(controls reportsummary.ControlSummaries) []reportsummary.ControlSummary {
	out := make([]reportsummary.ControlSummary, 0, len(controls))
	for _, ctrl := range controls {
		out = append(out, ctrl)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si := apis.ControlSeverityToInt(out[i].GetScoreFactor())
		sj := apis.ControlSeverityToInt(out[j].GetScoreFactor())
		if si != sj {
			return si > sj
		}
		return out[i].GetName() < out[j].GetName()
	})
	return out
}

func mdWriteSummaryTable(w io.Writer, controls []reportsummary.ControlSummary) error {
	ew := &mdErrWriter{w: w}
	ew.printf("## Summary\n\n")
	ew.printf("| Severity | Control | ID | Status | Failed | Passed |\n")
	ew.printf("|---|---|---|---|---|---|\n")

	for i := range controls {
		ctrl := &controls[i]
		lists := ctrl.ListResourcesIDs(nil)
		ew.printf("| %s | %s | %s | %s | %d | %d |\n",
			apis.ControlSeverityToString(ctrl.GetScoreFactor()),
			mdEscapeCell(ctrl.GetName()),
			ctrl.GetID(),
			mdStatusLabel(ctrl.GetStatus()),
			lists.Failed(),
			lists.Passed(),
		)
	}
	ew.printf("\n")
	return ew.err
}

func mdWriteFailedSection(ctx context.Context, w io.Writer, controls []reportsummary.ControlSummary, session *cautils.OPASessionObj) error {
	hasFailed := false
	for i := range controls {
		if controls[i].GetStatus().IsFailed() {
			hasFailed = true
			break
		}
	}
	if !hasFailed {
		return nil
	}

	ew := &mdErrWriter{w: w}
	ew.printf("## Failed Controls\n\n")

	for i := range controls {
		ctrl := &controls[i]
		if !ctrl.GetStatus().IsFailed() {
			continue
		}

		severity := apis.ControlSeverityToString(ctrl.GetScoreFactor())
		ew.printf("### %s — %s (`%s`)\n\n", ctrl.GetName(), severity, ctrl.GetID())

		if rem := ctrl.GetRemediation(); rem != "" {
			ew.printf("> **Remediation:** %s\n\n", rem)
		}

		ew.printf("[View documentation](%s)\n\n", cautils.GetControlLink(ctrl.GetID()))

		if ew.err != nil {
			return ew.err
		}

		failedIDs := ctrl.ListResourcesIDs(nil).GetItems(apis.StatusFailed)
		sort.Strings(failedIDs)

		if len(failedIDs) == 0 {
			continue
		}

		ew.printf("| Resource | Kind | Namespace |\n")
		ew.printf("|---|---|---|\n")

		for _, id := range failedIDs {
			res, ok := session.AllResources[id]
			if !ok {
				logger.L().Ctx(ctx).Debug("resource missing from AllResources", helpers.String("resourceID", id))
				ew.printf("| %s | — | — |\n", mdEscapeCell(id))
				continue
			}
			ew.printf("| %s | %s | %s |\n",
				mdEscapeCell(res.GetName()),
				mdEscapeCell(res.GetKind()),
				mdEscapeCell(res.GetNamespace()),
			)
		}
		ew.printf("\n")

		if ew.err != nil {
			return ew.err
		}
	}
	return ew.err
}

func mdWriteImageScanReport(w io.Writer, imageScanData []cautils.ImageScanData) error {
	summary := buildImageScanSummary(imageScanData)
	ew := &mdErrWriter{w: w}

	ew.printf("# Kubescape Image Scan Report\n\n")
	if len(summary.Images) == 1 {
		ew.printf("**Image:** `%s`\n\n", mdEscapeInline(summary.Images[0]))
	} else {
		ew.printf("**Images:** %d\n\n", len(summary.Images))
	}
	if summary.VulnDBBuilt != nil {
		ew.printf("**Vulnerability DB Built:** %s\n\n", summary.VulnDBBuilt.UTC().Format(time.RFC3339))
	}
	if ew.err != nil {
		return ew.err
	}

	if err := mdWriteImageTargets(w, summary.Images); err != nil {
		return err
	}
	if err := mdWriteImageSeveritySummary(w, summary.MapsSeverityToSummary); err != nil {
		return err
	}
	if err := mdWriteImagePackageSummary(w, summary.PackageScores); err != nil {
		return err
	}
	return mdWriteImageVulnerabilities(w, summary.CVEs)
}

func mdWriteImageTargets(w io.Writer, images []string) error {
	ew := &mdErrWriter{w: w}
	ew.printf("## Images\n\n")
	if len(images) == 0 {
		ew.printf("No image targets were scanned.\n\n")
		return ew.err
	}

	ew.printf("| Image |\n")
	ew.printf("|---|\n")
	for _, image := range images {
		ew.printf("| `%s` |\n", mdEscapeCell(image))
	}
	ew.printf("\n")
	return ew.err
}

func mdWriteImageSeveritySummary(w io.Writer, severities map[string]*imageprinter.SeveritySummary) error {
	ew := &mdErrWriter{w: w}
	ew.printf("## Vulnerability Summary\n\n")
	ew.printf("| Severity | CVEs | Fixable |\n")
	ew.printf("|---|---:|---:|\n")

	totalCVEs := 0
	totalFixable := 0
	for _, severity := range mdImageSeverityOrder(severities) {
		summary := severities[severity]
		totalCVEs += summary.NumberOfCVEs
		totalFixable += summary.NumberOfFixableCVEs
		ew.printf("| %s | %d | %d |\n", mdEscapeCell(severity), summary.NumberOfCVEs, summary.NumberOfFixableCVEs)
	}
	ew.printf("| **Total** | **%d** | **%d** |\n\n", totalCVEs, totalFixable)
	return ew.err
}

func mdWriteImagePackageSummary(w io.Writer, packages map[string]*imageprinter.PackageScore) error {
	ew := &mdErrWriter{w: w}
	ew.printf("## Affected Packages\n\n")
	if len(packages) == 0 {
		ew.printf("No affected packages were found.\n\n")
		return ew.err
	}

	ew.printf("| Package | Version | Score | Critical | High | Medium | Low | Unknown |\n")
	ew.printf("|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, pkg := range mdSortedImagePackages(packages) {
		ew.printf("| %s | %s | %d | %d | %d | %d | %d | %d |\n",
			mdEscapeCell(pkg.Name),
			mdEscapeCell(pkg.Version),
			pkg.Score,
			pkg.MapSeverityToCVEsNumber["Critical"],
			pkg.MapSeverityToCVEsNumber["High"],
			pkg.MapSeverityToCVEsNumber["Medium"],
			pkg.MapSeverityToCVEsNumber["Low"],
			mdUnknownSeverityCount(pkg.MapSeverityToCVEsNumber),
		)
	}
	ew.printf("\n")
	return ew.err
}

func mdWriteImageVulnerabilities(w io.Writer, cves []imageprinter.CVE) error {
	ew := &mdErrWriter{w: w}
	ew.printf("## Vulnerabilities\n\n")
	if len(cves) == 0 {
		ew.printf("No vulnerabilities were found.\n")
		return ew.err
	}

	ew.printf("| Severity | Vulnerability | Package | Version | Fixed In | Image |\n")
	ew.printf("|---|---|---|---|---|---|\n")
	for _, cve := range mdSortedImageCVEs(cves) {
		ew.printf("| %s | %s | %s | %s | %s | `%s` |\n",
			mdEscapeCell(cve.Severity),
			mdEscapeCell(cve.ID),
			mdEscapeCell(cve.Package),
			mdEscapeCell(cve.Version),
			mdEscapeCell(mdFixedIn(cve)),
			mdEscapeCell(cve.Image),
		)
	}
	return ew.err
}

func mdImageSeverityOrder(severities map[string]*imageprinter.SeveritySummary) []string {
	out := make([]string, 0, len(severities))
	for severity := range severities {
		out = append(out, severity)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri := tableutils.ImageSeverityToInt(out[i])
		rj := tableutils.ImageSeverityToInt(out[j])
		if ri != rj {
			return ri > rj
		}
		return out[i] < out[j]
	})
	return out
}

func mdSortedImagePackages(packages map[string]*imageprinter.PackageScore) []*imageprinter.PackageScore {
	out := make([]*imageprinter.PackageScore, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func mdSortedImageCVEs(cves []imageprinter.CVE) []imageprinter.CVE {
	out := append([]imageprinter.CVE(nil), cves...)
	sort.SliceStable(out, func(i, j int) bool {
		ri := tableutils.ImageSeverityToInt(out[i].Severity)
		rj := tableutils.ImageSeverityToInt(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Image < out[j].Image
	})
	return out
}

func mdUnknownSeverityCount(counts map[string]int) int {
	known := map[string]struct{}{
		"Critical": {},
		"High":     {},
		"Medium":   {},
		"Low":      {},
	}
	total := 0
	for severity, count := range counts {
		if _, ok := known[severity]; !ok {
			total += count
		}
	}
	return total
}

func mdFixedIn(cve imageprinter.CVE) string {
	switch cve.FixedState {
	case string(v5.FixedState):
		if len(cve.FixVersions) == 0 {
			return "fixed"
		}
		return strings.Join(cve.FixVersions, ", ")
	case string(v5.WontFixState):
		return cve.FixedState
	default:
		return ""
	}
}

func mdStatusLabel(status apis.IStatus) string {
	if status == nil {
		return "Unknown"
	}
	switch {
	case status.IsFailed():
		return "❌ Failed"
	case status.IsPassed():
		return "✅ Passed"
	case status.IsSkipped():
		return "⏭ Skipped"
	default:
		return string(status.Status())
	}
}

func mdEscapeCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func mdEscapeInline(s string) string {
	return strings.ReplaceAll(s, "`", "\\`")
}
