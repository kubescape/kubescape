package v2

import (
	"fmt"
	"sort"

	"github.com/armosec/opa-utils/reporthandling/apis"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/fatih/color"
)

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) []string {
	row := []string{controlSummary.GetName()}
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Excluded()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().All()))

	if controlSummary.GetStatus().IsPassed() {
		row = append(row, color.CyanString("Passed"))
	} else if controlSummary.GetStatus().IsSkipped() {
		row = append(row, "skipped")
	} else {
		row = append(row, setColor(apis.ControlSeverityToString(controlSummary.GetScoreFactor())))
	}

	if !controlSummary.GetStatus().IsSkipped() {
		row = append(row, fmt.Sprintf("%d", int(controlSummary.GetScore()))+"%")
		row = append(row, "")
	} else {
		row = append(row, string(controlSummary.GetStatus().Status()))
		if controlSummary.GetStatus().IsSkipped() {
			stars := ""
			for i := range infoToPrintInfo {
				if infoToPrintInfo[i].info == controlSummary.GetStatus().Info() {
					stars = infoToPrintInfo[i].stars
					break
				}
			}
			row = append(row, stars)
		} else {
			row = append(row, "")
		}
	}
	return row
}

func setColor(controlSeverity string) string {
	switch controlSeverity {
	case "Critical":
		return color.New(color.FgRed, color.Bold).Add(color.Underline).SprintFunc()(controlSeverity)
	case "High":
		return color.New(color.FgRed, color.Bold).SprintFunc()(controlSeverity)
	case "Medium":
		return color.New(color.FgYellow, color.Bold).SprintFunc()(controlSeverity)
	case "Low":
		return color.New(color.FgGreen, color.Bold).SprintFunc()(controlSeverity)
	default:
		return color.New(color.FgBlue, color.Bold).SprintFunc()(controlSeverity)
	}
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
	return []string{"CONTROL NAME", "FAILED RESOURCES", "EXCLUDED RESOURCES", "ALL RESOURCES", "SEVERITY", "% RISK-SCORE", "INFO"}
}
