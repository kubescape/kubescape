package v2

import (
	"fmt"
	"sort"

	"github.com/armosec/opa-utils/reporthandling/apis"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

const (
	columnSeverity       = iota
	columnName           = iota
	columnCounterFailed  = iota
	columnCounterExclude = iota
	columnCounterAll     = iota
	columnRiskScore      = iota
	columnInfo           = iota
	_rowLen              = iota
)

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars, verbose bool) []string {
	row := make([]string, _rowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	// ignore irelevant results
	if !verbose && (controlSummary.GetStatus().IsSkipped() && controlSummary.GetStatus().Status() == apis.StatusIrrelevant) {
		return []string{}
	}

	row[columnSeverity] = getSeverityColumn(controlSummary)
	row[columnName] = controlSummary.GetName()
	row[columnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[columnCounterExclude] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Excluded())
	row[columnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[columnRiskScore] = getRiskScoreColumn(controlSummary)
	row[columnInfo] = getInfoColumn(controlSummary, infoToPrintInfo)

	return row
}

func getInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	if !controlSummary.GetStatus().IsSkipped() {
		return ""
	}

	if controlSummary.GetStatus().IsSkipped() {
		for i := range infoToPrintInfo {
			if infoToPrintInfo[i].info == controlSummary.GetStatus().Info() {
				return infoToPrintInfo[i].stars
			}
		}
	}
	return ""
}

func getRiskScoreColumn(controlSummary reportsummary.IControlSummary) string {
	if controlSummary.GetStatus().IsSkipped() {
		return string(controlSummary.GetStatus().Status())
	}
	return fmt.Sprintf("%d", int(controlSummary.GetScore())) + "%"
}

func getSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	// if controlSummary.GetStatus().IsPassed() || controlSummary.GetStatus().IsSkipped() {
	// 	return " "
	// }
	severity := apis.ControlSeverityToString(controlSummary.GetScoreFactor())
	return color.New(getColor(severity), color.Bold).SprintFunc()(severity)
}
func getColor(controlSeverity string) color.Attribute {
	switch controlSeverity {
	case "Critical":
		return color.FgRed
	case "High":
		return color.FgYellow
	case "Medium":
		return color.FgCyan
	case "Low":
		return color.FgWhite
	default:
		return color.FgWhite
	}
}

func getSortedControlsNames(controls reportsummary.ControlSummaries) [][]string {
	controlNames := make([][]string, 5)
	for k := range controls {
		c := controls[k]
		i := apis.ControlSeverityToInt(c.GetScoreFactor())
		controlNames[i] = append(controlNames[i], c.GetName())
	}
	for i := range controlNames {
		sort.Strings(controlNames[i])
	}
	return controlNames
}

func getControlTableHeaders() []string {
	headers := make([]string, _rowLen)
	headers[columnName] = "CONTROL NAME"
	headers[columnCounterFailed] = "FAILED RESOURCES"
	headers[columnCounterExclude] = "EXCLUDED RESOURCES"
	headers[columnCounterAll] = "ALL RESOURCES"
	headers[columnSeverity] = "SEVERITY"
	headers[columnRiskScore] = "% RISK-SCORE"
	headers[columnInfo] = "INFO"
	return headers
}

func getColumnsAlignments() []int {
	alignments := make([]int, _rowLen)
	alignments[columnName] = tablewriter.ALIGN_LEFT
	alignments[columnCounterFailed] = tablewriter.ALIGN_CENTER
	alignments[columnCounterExclude] = tablewriter.ALIGN_CENTER
	alignments[columnCounterAll] = tablewriter.ALIGN_CENTER
	alignments[columnSeverity] = tablewriter.ALIGN_LEFT
	alignments[columnRiskScore] = tablewriter.ALIGN_CENTER
	alignments[columnRiskScore] = tablewriter.ALIGN_CENTER
	return alignments
}
