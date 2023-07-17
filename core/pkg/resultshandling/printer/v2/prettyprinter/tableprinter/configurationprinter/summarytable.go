package configurationprinter

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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

func GetControlTableHeaders() []string {
	headers := make([]string, _summaryRowLen)
	headers[summaryColumnName] = "CONTROL NAME"
	headers[summaryColumnCounterFailed] = "FAILED RESOURCES"
	headers[summaryColumnCounterAll] = "ALL RESOURCES"
	headers[summaryColumnSeverity] = "SEVERITY"
	headers[summaryColumnComplianceScore] = "% COMPLIANCE-SCORE"
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

func GenerateFooter(summaryDetails *reportsummary.SummaryDetails) []string {
	// Severity | Control name | failed resources | all resources | % success
	row := make([]string, _summaryRowLen)
	row[summaryColumnName] = "Resource Summary"
	row[summaryColumnCounterFailed] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed())
	row[summaryColumnCounterAll] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().All())
	row[summaryColumnSeverity] = " "
	row[summaryColumnComplianceScore] = fmt.Sprintf("%.2f%s", summaryDetails.ComplianceScore, "%")

	return row
}
