package printer

import (
	"fmt"
	"sort"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
		name:            utils.TruncateName(controlSummary.GetName(), controlNameMaxLength),
		counterFailed:   fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed()),
		counterAll:      fmt.Sprintf("%d", controlSummary.NumberOfResources().All()),
		severity:        apis.ControlSeverityToString(controlSummary.GetScoreFactor()),
		complianceScore: getComplianceScoreColumn(controlSummary, infoToPrintInfo),
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
	if compliance := cautils.ComplianceScoreToInt(controlSummary.GetComplianceScore()); compliance < 0 {
		return "N/A"
	} else {
		return fmt.Sprintf("%d", compliance) + "%"
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
		if i < 0 || i >= len(controlIDs) {
			i = 0
		}
		controlIDs[i] = append(controlIDs[i], c.GetID())
	}
	for i := range controlIDs {
		sort.Strings(controlIDs[i])
	}
	return controlIDs
}
