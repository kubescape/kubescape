package printer

import (
	"fmt"
	"kube-escape/cautils"
	"os"

	"kube-escape/cautils/k8sinterface"
	"kube-escape/cautils/opapolicy"

	"github.com/enescakir/emoji"
	"github.com/golang/glog"
	"github.com/olekukonko/tablewriter"
)

var INDENT = "   "

type Printer struct {
	opaSessionObj *chan *cautils.OPASessionObj
	summery       Summery
}

func NewPrinter(opaSessionObj *chan *cautils.OPASessionObj) *Printer {
	return &Printer{
		opaSessionObj: opaSessionObj,
		summery:       NewSummery(),
	}
}

func (printer *Printer) ActionPrint() {

	// recover
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("RECOVER in ActionSendReportListenner, reason: %v", err)
		}
	}()
	for {
		opaSessionObj := <-*printer.opaSessionObj

		printer.SummerySetup(opaSessionObj.PostureReport)
		printer.PrintResults()
		printer.PrintSummaryTable()

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

			printer.summery[cr.Name] = ControlSummery{
				TotalResources:  cr.GetNumberOfResources(),
				TotalFailed:     len(workloadsSummery),
				WorkloadSummery: mapResources,
				Description:     cr.Description,
			}
		}
	}
}

func (printer *Printer) PrintResults() {
	for control, controlSummery := range printer.summery {
		printer.printTitle(control, &controlSummery)
		printer.printResult(control, &controlSummery)

		if controlSummery.TotalResources > 0 {
			printer.printSummery(control, &controlSummery)
		}

	}
}

func (print *Printer) printSummery(controlName string, controlSummery *ControlSummery) {
	cautils.SimpleDisplay(os.Stdout, "Summary - ")
	cautils.SuccessDisplay(os.Stdout, "Passed:%v   ", controlSummery.TotalResources-controlSummery.TotalFailed)
	cautils.FailureDisplay(os.Stdout, "Failed:%v   ", controlSummery.TotalFailed)
	cautils.InfoDisplay(os.Stdout, "Total:%v\n\n", controlSummery.TotalResources)
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

	for k, v := range printer.summery {
		summaryTable.Append(generateRow(k, v))
		sumFailed += v.TotalFailed
		sumTotal += v.TotalResources
	}
	summaryTable.SetFooter(generateFooter(len(printer.summery), sumFailed, sumTotal))
	summaryTable.Render()
}
