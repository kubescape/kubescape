package printer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"sort"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"

	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

var INDENT = "   "

const EmptyPercentage = "NaN"

const (
	PrettyPrinter      string = "pretty-printer"
	JsonPrinter        string = "json"
	JunitResultPrinter string = "junit"
)

type Printer struct {
	writer             *os.File
	summary            Summary
	sortedControlNames []string
	printerType        string
	frameworkSummary   ControlSummary
}

func NewPrinter(printerType, outputFile string) *Printer {
	return &Printer{
		summary:     NewSummary(),
		writer:      getWriter(outputFile),
		printerType: printerType,
	}
}

func calculatePostureScore(postureReport *reporthandling.PostureReport) float32 {
	totalResources := 0
	totalFailed := 0
	for _, frameworkReport := range postureReport.FrameworkReports {
		totalFailed += frameworkReport.GetNumberOfFailedResources()
		totalResources += frameworkReport.GetNumberOfResources()
	}
	if totalResources == 0 {
		return float32(0)
	}
	return (float32(totalResources) - float32(totalFailed)) / float32(totalResources)
}

func (printer *Printer) ActionPrint(opaSessionObj *cautils.OPASessionObj) float32 {
	var score float32

	if printer.printerType == PrettyPrinter {
		printer.SummarySetup(opaSessionObj.PostureReport)
		printer.PrintResults()
		printer.PrintSummaryTable()
	} else if printer.printerType == JsonPrinter {
		postureReportStr, err := json.Marshal(opaSessionObj.PostureReport.FrameworkReports[0])
		if err != nil {
			fmt.Println("Failed to convert posture report object!")
			os.Exit(1)
		}
		printer.writer.Write(postureReportStr)
	} else if printer.printerType == JunitResultPrinter {
		junitResult, err := convertPostureReportToJunitResult(opaSessionObj.PostureReport)
		if err != nil {
			fmt.Println("Failed to convert posture report object!")
			os.Exit(1)
		}
		postureReportStr, err := xml.Marshal(junitResult)
		if err != nil {
			fmt.Println("Failed to convert posture report object!")
			os.Exit(1)
		}
		printer.writer.Write(postureReportStr)
	} else if !cautils.IsSilent() {
		fmt.Println("unknown output printer")
		os.Exit(1)
	}

	score = calculatePostureScore(opaSessionObj.PostureReport)

	return score
}

func (printer *Printer) SummarySetup(postureReport *reporthandling.PostureReport) {
	for _, fr := range postureReport.FrameworkReports {
		printer.frameworkSummary = ControlSummary{
			TotalResources: fr.GetNumberOfResources(),
			TotalFailed:    fr.GetNumberOfFailedResources(),
			TotalWarnign:   fr.GetNumberOfWarningResources(),
		}
		for _, cr := range fr.ControlReports {
			if len(cr.RuleReports) == 0 {
				continue
			}
			workloadsSummary := listResultSummary(cr.RuleReports)
			mapResources := groupByNamespace(workloadsSummary)

			printer.summary[cr.Name] = ControlSummary{
				TotalResources:  cr.GetNumberOfResources(),
				TotalFailed:     cr.GetNumberOfFailedResources(),
				TotalWarnign:    cr.GetNumberOfWarningResources(),
				WorkloadSummary: mapResources,
				Description:     cr.Description,
				Remediation:     cr.Remediation,
				ListInputKinds:  cr.ListControlsInputKinds(),
			}
		}
	}
	printer.sortedControlNames = printer.getSortedControlsNames()
}
func (printer *Printer) PrintResults() {
	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummary := printer.summary[printer.sortedControlNames[i]]
		printer.printTitle(printer.sortedControlNames[i], &controlSummary)
		printer.printResult(printer.sortedControlNames[i], &controlSummary)

		if printer.summary[printer.sortedControlNames[i]].TotalResources > 0 {
			printer.printSummary(printer.sortedControlNames[i], &controlSummary)
		}

	}
}

func (printer *Printer) printSummary(controlName string, controlSummary *ControlSummary) {
	cautils.SimpleDisplay(printer.writer, "Summary - ")
	cautils.SuccessDisplay(printer.writer, "Passed:%v   ", controlSummary.TotalResources-controlSummary.TotalFailed-controlSummary.TotalWarnign)
	cautils.WarningDisplay(printer.writer, "Excluded:%v   ", controlSummary.TotalWarnign)
	cautils.FailureDisplay(printer.writer, "Failed:%v   ", controlSummary.TotalFailed)
	cautils.InfoDisplay(printer.writer, "Total:%v\n", controlSummary.TotalResources)
	if controlSummary.TotalFailed > 0 {
		cautils.DescriptionDisplay(printer.writer, "Remediation: %v\n", controlSummary.Remediation)
	}
	cautils.DescriptionDisplay(printer.writer, "\n")

}

func (printer *Printer) printTitle(controlName string, controlSummary *ControlSummary) {
	cautils.InfoDisplay(printer.writer, "[control: %s] ", controlName)
	if controlSummary.TotalResources == 0 && len(controlSummary.ListInputKinds) > 0 {
		cautils.InfoDisplay(printer.writer, "resources not found %v\n", emoji.ConfusedFace)
	} else if controlSummary.TotalFailed != 0 {
		cautils.FailureDisplay(printer.writer, "failed %v\n", emoji.SadButRelievedFace)
	} else if controlSummary.TotalWarnign != 0 {
		cautils.WarningDisplay(printer.writer, "excluded %v\n", emoji.NeutralFace)
	} else {
		cautils.SuccessDisplay(printer.writer, "passed %v\n", emoji.ThumbsUp)
	}

	cautils.DescriptionDisplay(printer.writer, "Description: %s\n", controlSummary.Description)

}
func (printer *Printer) printResult(controlName string, controlSummary *ControlSummary) {

	indent := INDENT
	for ns, rsc := range controlSummary.WorkloadSummary {
		preIndent := indent
		if ns != "" {
			cautils.SimpleDisplay(printer.writer, "%sNamespace %s\n", indent, ns)
		}
		preIndent2 := indent
		for r := range rsc {
			indent += indent
			cautils.SimpleDisplay(printer.writer, fmt.Sprintf("%s%s - %s\n", indent, rsc[r].Kind, rsc[r].Name))
			indent = preIndent2
		}
		indent = preIndent
	}

}

func (printer *Printer) PrintUrl(url string) {
	cautils.InfoTextDisplay(printer.writer, url)
}

func generateRow(control string, cs ControlSummary) []string {
	row := []string{control}
	row = append(row, cs.ToSlice()...)
	if cs.TotalResources != 0 {
		row = append(row, fmt.Sprintf("%d%s", percentage(cs.TotalResources, cs.TotalFailed), "%"))
	} else {
		row = append(row, EmptyPercentage)
	}
	return row
}

func generateHeader() []string {
	return []string{"Control Name", "Failed Resources", "Excluded Resources", "All Resources", "% success"}
}

func percentage(big, small int) int {
	if big == 0 {
		if small == 0 {
			return 100
		}
		return 0
	}
	return int(float64(float64(big-small)/float64(big)) * 100)
}
func generateFooter(numControlers, sumFailed, sumWarning, sumTotal int) []string {
	// Control name | # failed resources | all resources | % success
	row := []string{}
	row = append(row, fmt.Sprintf("%d", numControlers))
	row = append(row, fmt.Sprintf("%d", sumFailed))
	row = append(row, fmt.Sprintf("%d", sumWarning))
	row = append(row, fmt.Sprintf("%d", sumTotal))
	if sumTotal != 0 {
		row = append(row, fmt.Sprintf("%d%s", percentage(sumTotal, sumFailed), "%"))
	} else {
		row = append(row, EmptyPercentage)
	}
	return row
}
func (printer *Printer) PrintSummaryTable() {
	summaryTable := tablewriter.NewWriter(printer.writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(generateHeader())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetAlignment(tablewriter.ALIGN_LEFT)

	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummary := printer.summary[printer.sortedControlNames[i]]
		summaryTable.Append(generateRow(printer.sortedControlNames[i], controlSummary))
		// sumFailed += controlSummary.TotalFailed
		// sumWarning += controlSummary.TotalWarnign
		// sumTotal += controlSummary.TotalResources
	}
	summaryTable.SetFooter(generateFooter(len(printer.summary), printer.frameworkSummary.TotalFailed, printer.frameworkSummary.TotalWarnign, printer.frameworkSummary.TotalResources))
	summaryTable.Render()
}

func (printer *Printer) getSortedControlsNames() []string {
	controlNames := make([]string, 0, len(printer.summary))
	for k := range printer.summary {
		controlNames = append(controlNames, k)
	}
	sort.Strings(controlNames)
	return controlNames
}

func getWriter(outputFile string) *os.File {
	os.Remove(outputFile)
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening file")
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}
