package configurationprinter

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	summaryColumnSeverity        = iota
	summaryColumnName            = iota
	summaryColumnCounterFailed   = iota
	summaryColumnCounterAll      = iota
	summaryColumnComplianceScore = iota
	_summaryRowLen               = iota
)

func ControlCountersForSummary(counters reportsummary.ICounters) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Passed: %d, Action Required: %d)", counters.All(), counters.Failed(), counters.Passed(), counters.Skipped())
}

func GetSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	return utils.GetColor(apis.ControlSeverityToInt(controlSummary.GetScoreFactor()))(apis.ControlSeverityToString(controlSummary.GetScoreFactor()))
}

func GetControlTableHeaders(short bool) []string {
	var headers []string
	if short {
		headers = make([]string, 1)
		headers[0] = "Controls"
	} else {
		headers = make([]string, _summaryRowLen)
		headers[summaryColumnName] = "Control Name"
		headers[summaryColumnCounterFailed] = "Failed Resources"
		headers[summaryColumnCounterAll] = "All Resources"
		headers[summaryColumnSeverity] = "Severity"
		headers[summaryColumnComplianceScore] = "% Compliance-Score"
	}
	return headers
}

func GetColumnsAlignments() []int {
	alignments := make([]int, _summaryRowLen)
	alignments[summaryColumnName] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnCounterFailed] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnCounterAll] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnSeverity] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnComplianceScore] = tablewriter.ALIGN_CENTER
	return alignments
}

func GenerateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars, verbose bool) []string {
	row := make([]string, _summaryRowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	row[summaryColumnSeverity] = GetSeverityColumn(controlSummary)
	if len(controlSummary.GetName()) > 50 {
		row[summaryColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[summaryColumnName] = controlSummary.GetName()
	}
	row[summaryColumnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[summaryColumnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[summaryColumnComplianceScore] = GetComplianceScoreColumn(controlSummary, infoToPrintInfo)

	return row
}

func GetComplianceScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) string {
	if controlSummary.GetStatus().IsSkipped() {
		return fmt.Sprintf("%s %s", "Action Required", GetInfoColumn(controlSummary, infoToPrintInfo))
	}
	return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetComplianceScore())) + "%"
}

func GetInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) string {
	for i := range infoToPrintInfo {
		if infoToPrintInfo[i].Info == controlSummary.GetStatus().Info() {
			return infoToPrintInfo[i].Stars
		}
	}
	return ""
}

func GenerateFooter(summaryDetails *reportsummary.SummaryDetails, short bool) []string {
	var row []string
	if short {
		row = make([]string, 1)
		row[0] = fmt.Sprintf("Resource Summary"+strings.Repeat(" ", 0)+"\n\nFailed Resources"+strings.Repeat(" ", 1)+": %d\nAll Resources"+strings.Repeat(" ", 4)+": %d\n%% Compliance-Score"+strings.Repeat(" ", 4)+": %.2f%%", summaryDetails.NumberOfResources().Failed(), summaryDetails.NumberOfResources().All(), summaryDetails.ComplianceScore)
	} else {
		// Severity | Control name | failed resources | all resources | % success
		row = make([]string, _summaryRowLen)
		row[summaryColumnName] = "Resource Summary"
		row[summaryColumnCounterFailed] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed())
		row[summaryColumnCounterAll] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().All())
		row[summaryColumnSeverity] = " "
		row[summaryColumnComplianceScore] = fmt.Sprintf("%.2f%s", summaryDetails.ComplianceScore, "%")
	}

	return row
}
