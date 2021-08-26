package printer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"kube-escape/cautils"
	"os"
	"sort"

	"kube-escape/cautils/k8sinterface"
	"kube-escape/cautils/opapolicy"

	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

var INDENT = "   "

const (
	PrettyPrinter      string = "pretty-printer"
	JsonPrinter        string = "json"
	JunitResultPrinter string = "junit"
)

type Printer struct {
	opaSessionObj      *chan *cautils.OPASessionObj
	summary            Summary
	sortedControlNames []string
	printerType        string
}

func NewPrinter(opaSessionObj *chan *cautils.OPASessionObj, printerType string) *Printer {
	return &Printer{
		opaSessionObj: opaSessionObj,
		summary:       NewSummery(),
		printerType:   printerType,
	}
}

func (printer *Printer) ActionPrint() {

	for {
		opaSessionObj := <-*printer.opaSessionObj

		if printer.printerType == PrettyPrinter {
			printer.SummerySetup(opaSessionObj.PostureReport)
			printer.PrintResults()
			printer.PrintSummaryTable()
		} else if printer.printerType == JsonPrinter {
			postureReportStr, err := json.Marshal(opaSessionObj.PostureReport.FrameworkReports[0])
			if err != nil {
				fmt.Println("Failed to convert posture report object!")
				os.Exit(1)
			}
			os.Stdout.Write(postureReportStr)
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
			os.Stdout.Write(postureReportStr)
		} else {
			fmt.Println("unknown output printer")
			os.Exit(1)
		}

		if !k8sinterface.RunningIncluster {
			break
		}
	}
}

func (printer *Printer) SummerySetup(postureReport *opapolicy.PostureReport) {
	for _, fr := range postureReport.FrameworkReports {
		for _, cr := range fr.ControlReports {
			if len(cr.RuleReports) == 0 {
				continue
			}
			workloadsSummery := listResultSummery(cr.RuleReports)
			mapResources := groupByNamespace(workloadsSummery)

			printer.summary[cr.Name] = ControlSummery{
				TotalResources:  cr.GetNumberOfResources(),
				TotalFailed:     len(workloadsSummery),
				WorkloadSummery: mapResources,
				Description:     cr.Description,
				Remediation:     cr.Remediation,
			}
		}
	}
	printer.sortedControlNames = printer.getSortedControlsNames()

}

func (printer *Printer) PrintResults() {
	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummery := printer.summary[printer.sortedControlNames[i]]
		printer.printTitle(printer.sortedControlNames[i], &controlSummery)
		printer.printResult(printer.sortedControlNames[i], &controlSummery)

		if printer.summary[printer.sortedControlNames[i]].TotalResources > 0 {
			printer.printSummery(printer.sortedControlNames[i], &controlSummery)
		}

	}
}

func (print *Printer) printSummery(controlName string, controlSummery *ControlSummery) {
	cautils.SimpleDisplay(os.Stdout, "Summary - ")
	cautils.SuccessDisplay(os.Stdout, "Passed:%v   ", controlSummery.TotalResources-controlSummery.TotalFailed)
	cautils.FailureDisplay(os.Stdout, "Failed:%v   ", controlSummery.TotalFailed)
	cautils.InfoDisplay(os.Stdout, "Total:%v\n", controlSummery.TotalResources)
	if controlSummery.TotalFailed > 0 {
		cautils.DescriptionDisplay(os.Stdout, "Remediation: %v\n", controlSummery.Remediation)
	}
	cautils.DescriptionDisplay(os.Stdout, "\n")

}

func (printer *Printer) printTitle(controlName string, controlSummery *ControlSummery) {
	cautils.InfoDisplay(os.Stdout, "[control: %s] ", controlName)
	if controlSummery.TotalResources == 0 {
		cautils.InfoDisplay(os.Stdout, "resources not found %v\n", emoji.ConfusedFace)
	} else if controlSummery.TotalFailed == 0 {
		cautils.SuccessDisplay(os.Stdout, "passed %v\n", emoji.ThumbsUp)
	} else {
		cautils.FailureDisplay(os.Stdout, "failed %v\n", emoji.SadButRelievedFace)
	}

	cautils.DescriptionDisplay(os.Stdout, "Description: %s\n", controlSummery.Description)

}
func (printer *Printer) printResult(controlName string, controlSummery *ControlSummery) {

	indent := INDENT
	for ns, rsc := range controlSummery.WorkloadSummery {
		preIndent := indent
		if ns != "" {
			cautils.SimpleDisplay(os.Stdout, "%sNamespace %s\n", indent, ns)
		}
		preIndent2 := indent
		for r := range rsc {
			indent += indent
			cautils.SimpleDisplay(os.Stdout, fmt.Sprintf("%s%s - %s\n", indent, rsc[r].Kind, rsc[r].Name))
			indent = preIndent2
		}
		indent = preIndent
	}

}

func generateRow(control string, cs ControlSummery) []string {
	row := []string{control}
	row = append(row, cs.ToSlice()...)
	row = append(row, fmt.Sprintf("%d%s", percentage(cs.TotalResources, cs.TotalFailed), "%"))
	return row
}

func generateHeader() []string {
	return []string{"Control Name", "Failed Resources", "All Resources", "% success"}
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
func generateFooter(numControlers, sumFailed, sumTotal int) []string {
	// Control name | # failed resources | all resources | % success
	row := []string{}
	row = append(row, fmt.Sprintf("%d", numControlers))
	row = append(row, fmt.Sprintf("%d", sumFailed))
	row = append(row, fmt.Sprintf("%d", sumTotal))
	row = append(row, fmt.Sprintf("%d%s", percentage(sumTotal, sumFailed), "%"))
	return row
}
func (printer *Printer) PrintSummaryTable() {
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(generateHeader())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetAlignment(tablewriter.ALIGN_LEFT)
	sumTotal := 0
	sumFailed := 0

	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummery := printer.summary[printer.sortedControlNames[i]]
		summaryTable.Append(generateRow(printer.sortedControlNames[i], controlSummery))
		sumFailed += controlSummery.TotalFailed
		sumTotal += controlSummery.TotalResources
	}
	summaryTable.SetFooter(generateFooter(len(printer.summary), sumFailed, sumTotal))
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
