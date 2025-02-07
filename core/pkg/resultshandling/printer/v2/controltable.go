package printer

import (
	"fmt"
	"sort"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const controlNameMaxLength = 70

type TableRow struct {
	ref             string
	name            string
	counterFailed   string
	counterAll      string
	severity        string
	complianceScore string
}

// generateTableRow is responsible for generating the row that will be printed in the table
func generateTableRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) *TableRow {
	tableRow := &TableRow{
		ref:             controlSummary.GetID(),
		name:            controlSummary.GetName(),
		counterFailed:   fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed()),
		counterAll:      fmt.Sprintf("%d", controlSummary.NumberOfResources().All()),
		severity:        apis.ControlSeverityToString(controlSummary.GetScoreFactor()),
		complianceScore: getComplianceScoreColumn(controlSummary, infoToPrintInfo),
	}
	if len(controlSummary.GetName()) > controlNameMaxLength {
		tableRow.name = controlSummary.GetName()[:controlNameMaxLength] + "..."
	}

	return tableRow
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
	if compliance := cautils.Float32ToInt(controlSummary.GetComplianceScore()); compliance < 0 {
		return "N/A"
	} else {
		return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetComplianceScore())) + "%"
	}

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
