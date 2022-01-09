package resourcemapping

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/olekukonko/tablewriter"
)

type PrettyPrinter struct {
	writer      *os.File
	verboseMode bool
}

func NewPrettyPrinter(verboseMode bool) *PrettyPrinter {
	return &PrettyPrinter{
		verboseMode: verboseMode,
	}
}

func (prettyPrinter *PrettyPrinter) printResourceTable(results []resourcesresults.Result) {

	summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
	summaryTable.SetAutoWrapText(true)
	summaryTable.SetAutoMergeCells(false)
	// summaryTable.SetCenterSeparator("=")
	// summaryTable.SetRowSeparator("*")
	// summaryTable.
	summaryTable.SetHeader(generateResourceHeader())
	summaryTable.SetHeaderLine(true)

	// For control scan framework will be nil
	for i := range results {
		// status := result.GetStatus(nil).Status()
		resourceID := results[i].GetResourceID()
		control := results[i].ListControls()
		if raw := generateResourceRow(resourceID, control, prettyPrinter.verboseMode); len(raw) > 0 {
			summaryTable.Append(raw)
		}
	}

	// alignments := []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER}
	// summaryTable.SetColumnAlignment(alignments)

	// for i := 0; i < len(prettyPrinter.sortedControlNames); i++ {
	// 	controlSummary := prettyPrinter.summary[prettyPrinter.sortedControlNames[i]]
	// 	summaryTable.Append(generateRow(prettyPrinter.sortedControlNames[i], controlSummary))
	// }

	// summaryTable.SetFooter(generateFooter(prettyPrinter))

	summaryTable.Render()
}

func (prettyPrinter *PrettyPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {

	prettyPrinter.printResourceTable(opaSessionObj.Report.Results)
	// var overallRiskScore float32 = 0
	// for _, frameworkReport := range opaSessionObj.PostureReport.FrameworkReports {
	// 	frameworkNames = append(frameworkNames, frameworkReport.Name)
	// 	frameworkScores = append(frameworkScores, frameworkReport.Score)
	// 	failedResources = reporthandling.GetUniqueResourcesIDs(append(failedResources, frameworkReport.ListResourcesIDs().GetFailedResources()...))
	// 	warningResources = reporthandling.GetUniqueResourcesIDs(append(warningResources, frameworkReport.ListResourcesIDs().GetWarningResources()...))
	// 	allResources = reporthandling.GetUniqueResourcesIDs(append(allResources, frameworkReport.ListResourcesIDs().GetAllResources()...))
	// 	prettyPrinter.summarySetup(frameworkReport, opaSessionObj.AllResources)
	// 	overallRiskScore += frameworkReport.Score
	// }

	// overallRiskScore /= float32(len(opaSessionObj.PostureReport.FrameworkReports))

	// prettyPrinter.frameworkSummary = ResultSummary{
	// 	RiskScore:      overallRiskScore,
	// 	TotalResources: len(allResources),
	// 	TotalFailed:    len(failedResources),
	// 	TotalWarning:   len(warningResources),
	// }

	// prettyPrinter.printResults()
	// prettyPrinter.printSummaryTable(frameworkNames, frameworkScores)

}

func (prettyPrinter *PrettyPrinter) SetWriter(outputFile string) {
	prettyPrinter.writer = printer.GetWriter(outputFile)
}

func (prettyPrinter *PrettyPrinter) FinalizeData(opaSessionObj *cautils.OPASessionObj) {
	// finalizeReport(opaSessionObj)
}
func (prettyPrinter *PrettyPrinter) Score(score float32) {
}

// func (prettyPrinter *PrettyPrinter) printSummary(controlName string, controlSummary *ResultSummary) {
// 	// cautils.SimpleDisplay(prettyPrinter.writer, "Summary - ")
// 	// cautils.SuccessDisplay(prettyPrinter.writer, "Passed:%v   ", controlSummary.TotalResources-controlSummary.TotalFailed-controlSummary.TotalWarning)
// 	// cautils.WarningDisplay(prettyPrinter.writer, "Excluded:%v   ", controlSummary.TotalWarning)
// 	// cautils.FailureDisplay(prettyPrinter.writer, "Failed:%v   ", controlSummary.TotalFailed)
// 	// cautils.InfoDisplay(prettyPrinter.writer, "Total:%v\n", controlSummary.TotalResources)
// 	// if controlSummary.TotalFailed > 0 {
// 	// 	cautils.DescriptionDisplay(prettyPrinter.writer, "Remediation: %v\n", controlSummary.Remediation)
// 	// }
// 	// cautils.DescriptionDisplay(prettyPrinter.writer, "\n")

// }

func generateResourceRow(resourceID string, controls []resourcesresults.ResourceAssociatedControl, verboseMode bool) []string {
	row := []string{}

	controlsNames := []string{}
	statuses := []string{}

	for i := range controls {
		if !verboseMode && controls[i].GetStatus(nil).IsPassed() {
			continue
		}
		if controls[i].GetName() == "" {
			continue
		}
		controlsNames = append(controlsNames, controls[i].GetName())
		statuses = append(statuses, string(controls[i].GetStatus(nil).Status()))
	}

	splitted := strings.Split(resourceID, "/")
	if len(splitted) < 5 || len(controlsNames) == 0 {
		return row
	}

	row = append(row, splitted[3])
	row = append(row, splitted[4])
	row = append(row, splitted[2])

	row = append(row, strings.Join(controlsNames, "\n"))
	row = append(row, strings.Join(statuses, "\n"))

	return row
}

// func generateRow(control string, cs ResultSummary) []string {
// 	row := []string{control}
// 	row = append(row, cs.ToSlice()...)
// 	if cs.TotalResources != 0 {
// 		row = append(row, fmt.Sprintf("%d", int(cs.RiskScore))+"%")
// 	} else {
// 		row = append(row, "skipped")
// 	}
// 	return row
// }

func generateResourceHeader() []string {
	return []string{"Kind", "Name", "Namespace", "Controls", "Statues"}
}
func generateHeader() []string {
	return []string{"Control Name", "Failed Resources", "Excluded Resources", "All Resources", "% risk-score"}
}

func generateFooter(prettyPrinter *PrettyPrinter) []string {
	// Control name | # failed resources | all resources | % success
	row := []string{}
	// row = append(row, "Resource Summary") //fmt.Sprintf(""%d", numControlers"))
	// row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalFailed))
	// row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalWarning))
	// row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalResources))
	// row = append(row, fmt.Sprintf("%.2f%s", prettyPrinter.frameworkSummary.RiskScore, "%"))

	return row
}
func (prettyPrinter *PrettyPrinter) printSummaryTable(frameworksNames []string, frameworkScores []float32) {
	// For control scan framework will be nil
	prettyPrinter.printFramework(frameworksNames, frameworkScores)

	summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
	// summaryTable.SetAutoWrapText(false)
	// summaryTable.SetHeader(generateHeader())
	// summaryTable.SetHeaderLine(true)
	// alignments := []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER}
	// summaryTable.SetColumnAlignment(alignments)

	// for i := 0; i < len(prettyPrinter.sortedControlNames); i++ {
	// 	controlSummary := prettyPrinter.summary[prettyPrinter.sortedControlNames[i]]
	// 	summaryTable.Append(generateRow(prettyPrinter.sortedControlNames[i], controlSummary))
	// }

	// summaryTable.SetFooter(generateFooter(prettyPrinter))

	summaryTable.Render()
}

func (prettyPrinter *PrettyPrinter) printFramework(frameworksNames []string, frameworkScores []float32) {
	if len(frameworksNames) == 1 {
		cautils.InfoTextDisplay(prettyPrinter.writer, fmt.Sprintf("FRAMEWORK %s\n", frameworksNames[0]))
	} else if len(frameworksNames) > 1 {
		p := "FRAMEWORKS: "
		for i := 0; i < len(frameworksNames)-1; i++ {
			p += fmt.Sprintf("%s (risk: %.2f), ", frameworksNames[i], frameworkScores[i])
		}
		p += fmt.Sprintf("%s (risk: %.2f)\n", frameworksNames[len(frameworksNames)-1], frameworkScores[len(frameworkScores)-1])
		cautils.InfoTextDisplay(prettyPrinter.writer, p)
	}
}

// func (prettyPrinter *PrettyPrinter) getSortedControlsNames() []string {
// 	controlNames := make([]string, 0, len(prettyPrinter.summary))
// 	for k := range prettyPrinter.summary {
// 		controlNames = append(controlNames, k)
// 	}
// 	sort.Strings(controlNames)
// 	return controlNames
// }
// func getControlURL(controlID string) string {
// 	return fmt.Sprintf("https://hub.armo.cloud/docs/%s", strings.ToLower(controlID))
// }
