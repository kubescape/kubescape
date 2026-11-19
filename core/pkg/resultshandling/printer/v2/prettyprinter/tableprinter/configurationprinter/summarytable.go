package configurationprinter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
	if counters == nil {
		return []table.Row{
			{"Controls", "0"},
			{"Passed", "0"},
			{"Failed", "0"},
			{"Action Required", "0"},
		}
	}
	rows := make([]table.Row, 0, 4)
	rows = append(rows, table.Row{"Controls", strconv.Itoa(counters.All())})
	rows = append(rows, table.Row{"Passed", strconv.Itoa(counters.Passed())})
	rows = append(rows, table.Row{"Failed", strconv.Itoa(counters.Failed())})
	rows = append(rows, table.Row{"Action Required", strconv.Itoa(counters.Skipped())})

	return rows
}

func GetSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	if controlSummary == nil {
		return ""
	}
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
	if controlSummary == nil {
		return table.Row{}
	}

	row := make(table.Row, _summaryRowLen)

	// ignore passed results
	status := controlSummary.GetStatus()
	if !verbose && status != nil && status.IsPassed() {
		return table.Row{}
	}

	var failedResources, allResources string
	if numRes := controlSummary.NumberOfResources(); numRes != nil {
		failedResources = fmt.Sprintf("%d", numRes.Failed())
		allResources = fmt.Sprintf("%d", numRes.All())
	}

	row[summaryColumnSeverity] = GetSeverityColumn(controlSummary)
	row[summaryColumnName] = utils.TruncateName(controlSummary.GetName(), utils.MaxControlNameLen)
	row[summaryColumnCounterFailed] = failedResources
	row[summaryColumnCounterAll] = allResources
	row[summaryColumnComplianceScore] = GetComplianceScoreColumn(controlSummary, infoToPrintInfo)

	return row
}

func GetComplianceScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) string {
	if controlSummary == nil {
		return ""
	}
	if status := controlSummary.GetStatus(); status != nil && status.IsSkipped() {
		return fmt.Sprintf("%s %s", "Action Required", GetInfoColumn(controlSummary, infoToPrintInfo))
	}
	rawScore := controlSummary.GetComplianceScore()
	if rawScore < 0 {
		return "N/A"
	}
	return fmt.Sprintf("%d%%", cautils.ComplianceScoreToInt(rawScore))
}

func GetInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) string {
	if controlSummary == nil || controlSummary.GetStatus() == nil {
		return ""
	}
	for i := range infoToPrintInfo {
		if infoToPrintInfo[i].Info == controlSummary.GetStatus().Info() {
			return infoToPrintInfo[i].Stars
		}
	}
	return ""
}

func GenerateFooter(summaryDetails *reportsummary.SummaryDetails, short bool) table.Row {
	if summaryDetails == nil {
		return table.Row{}
	}
	var row table.Row
	scoreStr := "N/A"
	if summaryDetails.ComplianceScore >= 0 {
		scoreStr = cautils.ComplianceScoreToString(summaryDetails.ComplianceScore, 2) + "%"
	}
	var failedResources, allResources int
	if numRes := summaryDetails.NumberOfResources(); numRes != nil {
		failedResources = numRes.Failed()
		allResources = numRes.All()
	}
	if short {
		row = make(table.Row, 1)
		row[0] = fmt.Sprintf("Resource Summary"+strings.Repeat(" ", 0)+"\n\nFailed Resources"+strings.Repeat(" ", 1)+": %d\nAll Resources"+strings.Repeat(" ", 4)+": %d\n%% Compliance-Score"+strings.Repeat(" ", 4)+": %s", failedResources, allResources, scoreStr)
	} else {
		// Severity | Control name | failed resources | all resources | % success
		row = make(table.Row, _summaryRowLen)
		row[summaryColumnName] = "Resource Summary"
		row[summaryColumnCounterFailed] = fmt.Sprintf("%d", failedResources)
		row[summaryColumnCounterAll] = fmt.Sprintf("%d", allResources)
		row[summaryColumnSeverity] = " "
		row[summaryColumnComplianceScore] = scoreStr
	}

	return row
}
