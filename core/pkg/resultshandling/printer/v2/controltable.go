package printer

import (
	"fmt"
	"sort"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	columnSeverity        = iota
	columnName            = iota
	columnCounterFailed   = iota
	columnCounterAll      = iota
	columnComplianceScore = iota
	_rowLen               = iota
)

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars, verbose bool) []string {
	row := make([]string, _rowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	row[columnSeverity] = getSeverityColumn(controlSummary)
	if len(controlSummary.GetName()) > 50 {
		row[columnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[columnName] = controlSummary.GetName()
	}
	row[columnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[columnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[columnComplianceScore] = getComplianceScoreColumn(controlSummary, infoToPrintInfo)
	if row[columnComplianceScore] == "-1%" {
		row[columnComplianceScore] = "N/A"
	}

	return row
}

func generateRowPdf(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars, verbose bool) []string {
	row := make([]string, _rowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	row[columnSeverity] = apis.ControlSeverityToString(controlSummary.GetScoreFactor())
	if len(controlSummary.GetName()) > 50 {
		row[columnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[columnName] = controlSummary.GetName()
	}
	row[columnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[columnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[columnComplianceScore] = getComplianceScoreColumn(controlSummary, infoToPrintInfo)

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

func getComplianceScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	if controlSummary.GetStatus().IsSkipped() {
		return fmt.Sprintf("%s %s", "Action Required", getInfoColumn(controlSummary, infoToPrintInfo))
	}
	return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetComplianceScore())) + "%"
}

func getSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	return getColor(apis.ControlSeverityToInt(controlSummary.GetScoreFactor()))(apis.ControlSeverityToString(controlSummary.GetScoreFactor()))
}

func getColor(controlSeverity int) (func(...string) string) {
	switch controlSeverity {
	case apis.SeverityCritical:
		return gchalk.WithAnsi256(1).Bold
	case apis.SeverityHigh:
		return gchalk.WithAnsi256(196).Bold
	case apis.SeverityMedium:
		return gchalk.WithAnsi256(166).Bold
	case apis.SeverityLow:
		return gchalk.WithAnsi256(220).Bold
	default:
		return gchalk.WithAnsi256(16).Bold
	}
}

func getSortedControlsIDs(controls reportsummary.ControlSummaries) [][]string {
	controlIDs := make([][]string, 5)
	for k := range controls {
		c := controls[k]
		i := apis.ControlSeverityToInt(c.GetScoreFactor())
		controlIDs[i] = append(controlIDs[i], c.GetID())
	}
	for i := range controlIDs {
		sort.Strings(controlIDs[i])
	}
	return controlIDs
}

/* unused for now
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
*/

func getControlTableHeaders() []string {
	headers := make([]string, _rowLen)
	headers[columnName] = "CONTROL NAME"
	headers[columnCounterFailed] = "FAILED RESOURCES"
	headers[columnCounterAll] = "ALL RESOURCES"
	headers[columnSeverity] = "SEVERITY"
	headers[columnComplianceScore] = "% COMPLIANCE-SCORE"
	return headers
}

func getColumnsAlignments() []int {
	alignments := make([]int, _rowLen)
	alignments[columnName] = tablewriter.ALIGN_LEFT
	alignments[columnCounterFailed] = tablewriter.ALIGN_CENTER
	alignments[columnCounterAll] = tablewriter.ALIGN_CENTER
	alignments[columnSeverity] = tablewriter.ALIGN_LEFT
	alignments[columnComplianceScore] = tablewriter.ALIGN_CENTER
	return alignments
}
