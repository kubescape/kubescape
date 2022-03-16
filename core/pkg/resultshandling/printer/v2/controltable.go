package v2

import (
	"fmt"
	"sort"

	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
)

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfoMap map[string]string) []string {
	row := []string{controlSummary.GetName()}
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Excluded()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().All()))

	if !controlSummary.GetStatus().IsSkipped() {
		row = append(row, fmt.Sprintf("%d", int(controlSummary.GetScore()))+"%")
		row = append(row, "")
	} else {
		row = append(row, string(controlSummary.GetStatus().Status()))
		if controlSummary.GetStatus().IsSkipped() {
			row = append(row, infoToPrintInfoMap[controlSummary.GetStatus().Info()])
		} else {
			row = append(row, "")
		}
	}
	return row
}

func getSortedControlsNames(controls reportsummary.ControlSummaries) []string {
	controlNames := make([]string, 0, len(controls))
	for k := range controls {
		c := controls[k]
		controlNames = append(controlNames, c.GetName())
	}
	sort.Strings(controlNames)
	return controlNames
}

func getControlTableHeaders() []string {
	return []string{"CONTROL NAME", "FAILED RESOURCES", "EXCLUDED RESOURCES", "ALL RESOURCES", "% RISK-SCORE", "INFO"}
}
