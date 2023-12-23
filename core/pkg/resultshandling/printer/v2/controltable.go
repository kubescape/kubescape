package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
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

func shortFormatRow(dataRows [][]string) [][]string {
	rows := [][]string{}
	for _, dataRow := range dataRows {
		rows = append(rows, []string{fmt.Sprintf("Severity"+strings.Repeat(" ", 11)+": %+v\nControl Name"+strings.Repeat(" ", 7)+": %+v\nFailed Resources"+strings.Repeat(" ", 3)+": %+v\nAll Resources"+strings.Repeat(" ", 6)+": %+v\n%% Compliance-Score"+strings.Repeat(" ", 1)+": %+v", dataRow[columnSeverity], dataRow[columnName], dataRow[columnCounterFailed], dataRow[columnCounterAll], dataRow[columnComplianceScore])})
	}
	return rows
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

func getColor(controlSeverity int) func(...string) string {
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

func getControlTableHeaders(short bool) []string {
	var headers []string
	if short {
		headers = make([]string, 1)
		headers[0] = "Controls"
	} else {
		headers = make([]string, _rowLen)
		headers[columnName] = "Control name"
		headers[columnCounterFailed] = "Failed resources"
		headers[columnCounterAll] = "All resources"
		headers[columnSeverity] = "Severity"
		headers[columnComplianceScore] = "Compliance score"
	}
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
