package configurationprinter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	summaryColumnSeverity        = iota
	summaryColumnName            = iota
	summaryColumnCounterFailed   = iota
	summaryColumnCounterAll      = iota
	summaryColumnComplianceScore = iota
	_summaryRowLen               = iota
)

func ControlCountersForSummary(counters reportsummary.ICounters) []table.Row {
	rows := make([]table.Row, 0, 4)
	rows = append(rows, table.Row{"Controls", strconv.Itoa(counters.All())})
	rows = append(rows, table.Row{"Passed", strconv.Itoa(counters.Passed())})
	rows = append(rows, table.Row{"Failed", strconv.Itoa(counters.Failed())})
	rows = append(rows, table.Row{"Action Required", strconv.Itoa(counters.Skipped())})

	return rows
}

func GetSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	return utils.GetColor(apis.ControlSeverityToInt(controlSummary.GetScoreFactor()))(apis.ControlSeverityToString(controlSummary.GetScoreFactor()))
}

func GetControlTableHeaders(short bool) table.Row {
	var headers table.Row
	if short {
		headers = make(table.Row, 1)
		headers[0] = "Controls"
	} else {
		headers = make(table.Row, _summaryRowLen)
		headers[summaryColumnName] = "Control name"
		headers[summaryColumnCounterFailed] = "Failed resources"
		headers[summaryColumnCounterAll] = "All Resources"
		headers[summaryColumnSeverity] = "Severity"
		headers[summaryColumnComplianceScore] = "Compliance score"
	}
	return headers
}

func GetColumnsAlignments() []table.ColumnConfig {
	return []table.ColumnConfig{
		{Number: summaryColumnSeverity + 1, Align: text.AlignCenter},
		{Number: summaryColumnName + 1, Align: text.AlignLeft},
		{Number: summaryColumnCounterFailed + 1, Align: text.AlignCenter},
		{Number: summaryColumnCounterAll + 1, Align: text.AlignCenter},
		{Number: summaryColumnComplianceScore + 1, Align: text.AlignCenter},
	}
}

func GenerateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars, verbose bool) table.Row {
	row := make(table.Row, _summaryRowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return table.Row{}
	}

	row[summaryColumnSeverity] = GetSeverityColumn(controlSummary)
	if len(controlSummary.GetName()) > 50 {
		row[summaryColumnName] = controlSummary.GetName()[:50] + "..." //nolint:gosec // Safe: row has length _summaryRowLen (5), accessing index 1
	} else {
		row[summaryColumnName] = controlSummary.GetName() //nolint:gosec // Safe: row has length _summaryRowLen (5), accessing index 1
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

func GenerateFooter(summaryDetails *reportsummary.SummaryDetails, short bool) table.Row {
	var row table.Row
	if short {
		row = make(table.Row, 1)
		row[0] = fmt.Sprintf("Resource Summary"+strings.Repeat(" ", 0)+"\n\nFailed Resources"+strings.Repeat(" ", 1)+": %d\nAll Resources"+strings.Repeat(" ", 4)+": %d\n%% Compliance-Score"+strings.Repeat(" ", 4)+": %.2f%%", summaryDetails.NumberOfResources().Failed(), summaryDetails.NumberOfResources().All(), summaryDetails.ComplianceScore)
	} else {
		// Severity | Control name | failed resources | all resources | % success
		row = make(table.Row, _summaryRowLen)
		row[summaryColumnName] = "Resource Summary"
		row[summaryColumnCounterFailed] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed())
		row[summaryColumnCounterAll] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().All())
		row[summaryColumnSeverity] = " "
		row[summaryColumnComplianceScore] = fmt.Sprintf("%.2f%s", summaryDetails.ComplianceScore, "%")
	}

	return row
}
