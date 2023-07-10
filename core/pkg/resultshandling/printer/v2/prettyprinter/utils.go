package prettyprinter

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
	"k8s.io/utils/strings/slices"
)

const (
	categoriesColumnSeverity  = iota
	categoriesColumnName      = iota
	categoriesColumnFailed    = iota
	categoriesColumnNextSteps = iota
)

var (
	mapScanTypeToOutput = map[cautils.ScanTypes]string{
		cautils.ScanTypeCluster: "Security Overview",
	}
	complianceFrameworks = []string{"nsa", "mitre"}
)

func mapCategoryToControlSummaries(summaryDetails reportsummary.SummaryDetails, sortedControlIDs [][]string) map[string][]reportsummary.IControlSummary {
	categories := map[string][]reportsummary.IControlSummary{}

	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			ctrl := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c)
			if ctrl.GetStatus().Status() == apis.StatusPassed {
				continue
			}
			for j := range ctrl.GetCategories() {
				categories[ctrl.GetCategories()[j]] = append(categories[ctrl.GetCategories()[j]], ctrl)
			}
		}
	}

	return categories
}

func generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)
	row[categoriesColumnSeverity] = getSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	row[categoriesColumnFailed] = fmt.Sprintf("%s", controlSummary.GetStatus().Status())
	row[categoriesColumnNextSteps] = generateNextSteps(controlSummary)

	return row
}

func generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("$ kubescape scan control %s", controlSummary.GetID())
}

func getCategoriesTableHeaders() []string {
	headers := make([]string, 4)
	headers[categoriesColumnSeverity] = "SEVERITY"
	headers[categoriesColumnName] = "CONTROL NAME"
	headers[categoriesColumnFailed] = "FAILED RESOURCES"
	headers[categoriesColumnNextSteps] = "NEXT STEPS"

	return headers
}

func getCategoriesColumnsAlignments() []int {
	alignments := make([]int, 4)
	alignments[categoriesColumnSeverity] = tablewriter.ALIGN_LEFT
	alignments[categoriesColumnName] = tablewriter.ALIGN_LEFT
	alignments[categoriesColumnFailed] = tablewriter.ALIGN_CENTER
	alignments[categoriesColumnNextSteps] = tablewriter.ALIGN_LEFT

	return alignments
}

func renderSingleCategory(writer *os.File, category string, ctrls []reportsummary.IControlSummary, categoriesTable *tablewriter.Table) {
	cautils.InfoTextDisplay(writer, "\n"+category+"\n")

	categoriesTable.ClearRows()
	for i := range ctrls {
		row := generateCategoriesRow(ctrls[i])
		if len(row) > 0 {
			categoriesTable.Append(row)
		}
	}
	categoriesTable.Render()
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

type infoStars struct {
	stars string
	info  string
}

func mapInfoToPrintInfo(controls reportsummary.ControlSummaries) []infoStars {
	infoToPrintInfo := []infoStars{}
	infoToPrintInfoMap := map[string]interface{}{}
	starCount := "*"
	for _, control := range controls {
		if control.GetStatus().IsSkipped() && control.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[control.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, infoStars{
					info:  control.GetStatus().Info(),
					stars: starCount,
				})
				starCount += "*"
				infoToPrintInfoMap[control.GetStatus().Info()] = nil
			}
		}
	}
	return infoToPrintInfo
}

func printInfo(writer *os.File, infoToPrintInfo []infoStars) {
	fmt.Println()
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(writer, fmt.Sprintf("%s %s\n", infoToPrintInfo[i].stars, infoToPrintInfo[i].info))
	}
}
func frameworksScoresToString(frameworks []reportsummary.IFrameworkSummary) string {
	if len(frameworks) == 1 {
		if frameworks[0].GetName() != "" {
			return fmt.Sprintf("FRAMEWORK %s\n", frameworks[0].GetName())
			// cautils.InfoTextDisplay(prettyPrinter.writer, ))
		}
	} else if len(frameworks) > 1 {
		p := "FRAMEWORKS: "
		i := 0
		for ; i < len(frameworks)-1; i++ {
			p += fmt.Sprintf("%s (compliance: %.2f), ", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		}
		p += fmt.Sprintf("%s (compliance: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		return p
	}
	return ""
}

func printComplianceScore(writer *os.File, frameworks []reportsummary.IFrameworkSummary) {
	cautils.InfoTextDisplay(writer, "Compliance Score:\n")
	for _, fw := range frameworks {
		cautils.SimpleDisplay(writer, "* %s: %.2f\n", fw.GetName(), fw.GetComplianceScore())
	}

	cautils.InfoTextDisplay(writer, "\n")
}

func filterComplianceFrameworks(frameworks []reportsummary.IFrameworkSummary) []reportsummary.IFrameworkSummary {
	complianceFws := []reportsummary.IFrameworkSummary{}
	for _, fw := range frameworks {
		if slices.Contains(complianceFrameworks, strings.ToLower(fw.GetName())) {
			complianceFws = append(complianceFws, fw)
		}
	}
	return complianceFws
}

func getSeparator(sep string) string {
	s := ""
	for i := 0; i < 80; i++ {
		s += sep
	}
	return s
}

func generateFooter(summaryDetails *reportsummary.SummaryDetails) []string {
	// Severity | Control name | failed resources | all resources | % success
	row := make([]string, _summaryRowLen)
	row[summaryColumnName] = "Resource Summary"
	row[summaryColumnCounterFailed] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed())
	row[summaryColumnCounterAll] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().All())
	row[summaryColumnSeverity] = " "
	row[summaryColumnComplianceScore] = fmt.Sprintf("%.2f%s", summaryDetails.ComplianceScore, "%")

	return row
}

func ControlCountersForSummary(counters reportsummary.ICounters) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Passed: %d, Action Required: %d)", counters.All(), counters.Failed(), counters.Passed(), counters.Skipped())
}

func ControlCountersForResource(l *helpersv1.AllLists) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, action required: %d)", l.Len(), l.Failed(), l.Skipped())
}

// renderSeverityCountersSummary renders the string that reports severity counters summary
func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) string {
	critical := counters.NumberOfCriticalSeverity()
	high := counters.NumberOfHighSeverity()
	medium := counters.NumberOfMediumSeverity()
	low := counters.NumberOfLowSeverity()

	return fmt.Sprintf(
		"Failed Resources by Severity: Critical — %d, High — %d, Medium — %d, Low — %d",
		critical, high, medium, low,
	)
}

func getControlTableHeaders() []string {
	headers := make([]string, _summaryRowLen)
	headers[summaryColumnName] = "CONTROL NAME"
	headers[summaryColumnCounterFailed] = "FAILED RESOURCES"
	headers[summaryColumnCounterAll] = "ALL RESOURCES"
	headers[summaryColumnSeverity] = "SEVERITY"
	headers[summaryColumnComplianceScore] = "% COMPLIANCE-SCORE"
	return headers
}

func getColumnsAlignments() []int {
	alignments := make([]int, _summaryRowLen)
	alignments[summaryColumnName] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnCounterFailed] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnCounterAll] = tablewriter.ALIGN_CENTER
	alignments[summaryColumnSeverity] = tablewriter.ALIGN_LEFT
	alignments[summaryColumnComplianceScore] = tablewriter.ALIGN_CENTER
	return alignments
}

func generateRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars, verbose bool) []string {
	row := make([]string, _summaryRowLen)

	// ignore passed results
	if !verbose && (controlSummary.GetStatus().IsPassed()) {
		return []string{}
	}

	row[summaryColumnSeverity] = getSeverityColumn(controlSummary)
	if len(controlSummary.GetName()) > 50 {
		row[summaryColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[summaryColumnName] = controlSummary.GetName()
	}
	row[summaryColumnCounterFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[summaryColumnCounterAll] = fmt.Sprintf("%d", controlSummary.NumberOfResources().All())
	row[summaryColumnComplianceScore] = getComplianceScoreColumn(controlSummary, infoToPrintInfo)

	return row
}

func getComplianceScoreColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	if controlSummary.GetStatus().IsSkipped() {
		return fmt.Sprintf("%s %s", "Action Required", getInfoColumn(controlSummary, infoToPrintInfo))
	}
	return fmt.Sprintf("%d", cautils.Float32ToInt(controlSummary.GetComplianceScore())) + "%"
}

func getInfoColumn(controlSummary reportsummary.IControlSummary, infoToPrintInfo []infoStars) string {
	for i := range infoToPrintInfo {
		if infoToPrintInfo[i].info == controlSummary.GetStatus().Info() {
			return infoToPrintInfo[i].stars
		}
	}
	return ""
}

func getWorkloadPrefixForCmd(namespace, kind, name string) string {
	if namespace == "" {
		return fmt.Sprintf("name: %s, kind: %s", name, kind)
	}
	return fmt.Sprintf("namespace: %s, name: %s, kind: %s", namespace, name, kind)
}
