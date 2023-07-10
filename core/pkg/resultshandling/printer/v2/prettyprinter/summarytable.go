package prettyprinter

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

func ControlCountersForSummary(counters reportsummary.ICounters) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Passed: %d, Action Required: %d)", counters.All(), counters.Failed(), counters.Passed(), counters.Skipped())
}

// renderSeverityCountersSummary renders the string that reports severity counters summary
func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) string {
	critical := counters.NumberOfCriticalSeverity()
	high := counters.NumberOfHighSeverity()
	medium := counters.NumberOfMediumSeverity()
	low := counters.NumberOfLowSeverity()

	return fmt.Sprintf(
		"Failed Resources by Severity: Critical — %d, High — %d, Medium — %d, Low — %d",
		critical, high, medium, low,
	)
}

func getControlTableHeaders() []string {
	headers := make([]string, _summaryRowLen)
	headers[summaryColumnName] = "CONTROL NAME"
	headers[summaryColumnCounterFailed] = "FAILED RESOURCES"
	headers[summaryColumnCounterAll] = "ALL RESOURCES"
	headers[summaryColumnSeverity] = "SEVERITY"
	headers[summaryColumnComplianceScore] = "% COMPLIANCE-SCORE"
	return headers
}

func getColumnsAlignments() []int {
	alignments := make([]int, _summaryRowLen)
	alignments[summaryColumnName] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnCounterFailed] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnCounterAll] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnSeverity] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnComplianceScore] = tablewriter.ALIGN_CENTER
	return alignments
}

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars, verbose bool) []string {
	row := make([]string, _summaryRowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	row[summaryColumnSeverity] = getSeverityColumn(controlSummary)
	if len(controlSummary.GetName()) > 50 {
		row[summaryColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[summaryColumnName] = controlSummary.GetName()
	}
	row[summaryColumnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[summaryColumnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[summaryColumnComplianceScore] = getComplianceScoreColumn(controlSummary, infoToPrintInfo)

	return row
}

func getComplianceScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	if controlSummary.GetStatus().IsSkipped() {
		return fmt.Sprintf("%s %s", "Action Required", getInfoColumn(controlSummary, infoToPrintInfo))
	}
	return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetComplianceScore())) + "%"
}

func getInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	for i := range infoToPrintInfo {
		if infoToPrintInfo[i].info == controlSummary.GetStatus().Info() {
			return infoToPrintInfo[i].stars
		}
	}
	return ""
}
