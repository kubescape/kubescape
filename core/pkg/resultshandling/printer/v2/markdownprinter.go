package printer

import (
	"context"
	"fmt"
	"io"
	"os"
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
	explicitOutput := outputFile != ""
	outputFile = printer.ResolveOutputPath(printer.MarkdownFormat, outputFile)
	if outputFile == "" {
		outputFile = markdownOutputFile + printer.MarkdownOutputExt
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
