package printer

import (
	"fmt"
	"sort"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	columnSeverity        = iota
	columnRef             = iota
	columnName            = iota
	columnCounterFailed   = iota
	columnCounterAll      = iota
	columnComplianceScore = iota
	_rowLen               = iota
	controlNameMaxLength  = 70
)

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
