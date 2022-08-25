package v2

import (
	"fmt"
	"sort"

	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	columnSeverity       = iota
	columnName           = iota
	columnCounterFailed  = iota
	columnCounterExclude = iota
	columnCounterAll     = iota
	columnRiskScore      = iota
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
	row[columnRiskScore] = getRiskScoreColumn(controlSummary, infoToPrintInfo)

	return row
}

func getInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	for i := range infoToPrintInfo {
		if infoToPrintInfo[i].info == controlSummary.GetStatus().Info() {
			return infoToPrintInfo[i].stars
		}
	}
	return ""
}

func getRiskScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	if controlSummary.GetStatus().IsSkipped() {
		return fmt.Sprintf("%s%s", controlSummary.GetStatus().Status(), getInfoColumn(controlSummary, infoToPrintInfo))
	}
	return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetScore())) + "%"
}

func getSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	return color.New(getColor(apis.ControlSeverityToInt(controlSummary.GetScoreFactor())), color.Bold).SprintFunc()(apis.ControlSeverityToString(controlSummary.GetScoreFactor()))
}
func getColor(controlSeverity int) color.Attribute {
	switch controlSeverity {
	case apis.SeverityCritical:
		return color.FgRed
	case apis.SeverityHigh:
		return color.FgYellow
	case apis.SeverityMedium:
		return color.FgCyan
	case apis.SeverityLow:
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
	return alignments
}
