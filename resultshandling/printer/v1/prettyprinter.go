package v1

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
)

type PrettyPrinter struct {
	writer             *os.File
	summary            Summary
	verboseMode        bool
	sortedControlNames []string
	frameworkSummary   ResultSummary
}

func NewPrettyPrinter(verboseMode bool) *PrettyPrinter {
	return &PrettyPrinter{
		verboseMode: verboseMode,
		summary:     NewSummary(),
	}
}

func (prettyPrinter *PrettyPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	overallRiskScore := opaSessionObj.Report.SummaryDetails.Score
	cautils.ReportV2ToV1(opaSessionObj)

	// score := calculatePostureScore(opaSessionObj.PostureReport)
	failedResources := []string{}
	warningResources := []string{}
	allResources := []string{}
	frameworkNames := []string{}
	frameworkScores := []float32{}

	for _, frameworkReport := range opaSessionObj.PostureReport.FrameworkReports {
		frameworkNames = append(frameworkNames, frameworkReport.Name)
		frameworkScores = append(frameworkScores, frameworkReport.Score)
		failedResources = reporthandling.GetUniqueResourcesIDs(append(failedResources, frameworkReport.ListResourcesIDs().GetFailedResources()...))
		warningResources = reporthandling.GetUniqueResourcesIDs(append(warningResources, frameworkReport.ListResourcesIDs().GetWarningResources()...))
		allResources = reporthandling.GetUniqueResourcesIDs(append(allResources, frameworkReport.ListResourcesIDs().GetAllResources()...))
		prettyPrinter.summarySetup(frameworkReport, opaSessionObj.AllResources)
	}

	prettyPrinter.frameworkSummary = ResultSummary{
		RiskScore:      overallRiskScore,
		TotalResources: len(allResources),
		TotalFailed:    len(failedResources),
		TotalWarning:   len(warningResources),
	}

	prettyPrinter.printResults()
	prettyPrinter.printSummaryTable(frameworkNames, frameworkScores)

}

func (prettyPrinter *PrettyPrinter) SetWriter(outputFile string) {
	prettyPrinter.writer = printer.GetWriter(outputFile)
}

func (prettyPrinter *PrettyPrinter) Score(score float32) {
}

func (prettyPrinter *PrettyPrinter) summarySetup(fr reporthandling.FrameworkReport, allResources map[string]workloadinterface.IMetadata) {

	for _, cr := range fr.ControlReports {
		// if len(cr.RuleReports) == 0 {
		// 	continue
		// }
		workloadsSummary := listResultSummary(cr.RuleReports, allResources)

		var passedWorkloads map[string][]WorkloadSummary
		if prettyPrinter.verboseMode {
			passedWorkloads = groupByNamespaceOrKind(workloadsSummary, workloadSummaryPassed)
		}

		//controlSummary
		prettyPrinter.summary[cr.Name] = ResultSummary{
			ID:                cr.ControlID,
			RiskScore:         cr.Score,
			TotalResources:    cr.GetNumberOfResources(),
			TotalFailed:       cr.GetNumberOfFailedResources(),
			TotalWarning:      cr.GetNumberOfWarningResources(),
			FailedWorkloads:   groupByNamespaceOrKind(workloadsSummary, workloadSummaryFailed),
			ExcludedWorkloads: groupByNamespaceOrKind(workloadsSummary, workloadSummaryExclude),
			PassedWorkloads:   passedWorkloads,
			Description:       cr.Description,
			Remediation:       cr.Remediation,
			ListInputKinds:    cr.ListControlsInputKinds(),
		}

	}
	prettyPrinter.sortedControlNames = prettyPrinter.getSortedControlsNames()
}
func (prettyPrinter *PrettyPrinter) printResults() {
	for i := 0; i < len(prettyPrinter.sortedControlNames); i++ {
		controlSummary := prettyPrinter.summary[prettyPrinter.sortedControlNames[i]]
		prettyPrinter.printTitle(prettyPrinter.sortedControlNames[i], &controlSummary)
		prettyPrinter.printResources(&controlSummary)
		if prettyPrinter.summary[prettyPrinter.sortedControlNames[i]].TotalResources > 0 {
			prettyPrinter.printSummary(prettyPrinter.sortedControlNames[i], &controlSummary)
		}

	}
}

func (prettyPrinter *PrettyPrinter) printSummary(controlName string, controlSummary *ResultSummary) {
	cautils.SimpleDisplay(prettyPrinter.writer, "Summary - ")
	cautils.SuccessDisplay(prettyPrinter.writer, "Passed:%v   ", controlSummary.TotalResources-controlSummary.TotalFailed-controlSummary.TotalWarning)
	cautils.WarningDisplay(prettyPrinter.writer, "Excluded:%v   ", controlSummary.TotalWarning)
	cautils.FailureDisplay(prettyPrinter.writer, "Failed:%v   ", controlSummary.TotalFailed)
	cautils.InfoDisplay(prettyPrinter.writer, "Total:%v\n", controlSummary.TotalResources)
	if controlSummary.TotalFailed > 0 {
		cautils.DescriptionDisplay(prettyPrinter.writer, "Remediation: %v\n", controlSummary.Remediation)
	}
	cautils.DescriptionDisplay(prettyPrinter.writer, "\n")

}
func (prettyPrinter *PrettyPrinter) printTitle(controlName string, controlSummary *ResultSummary) {
	cautils.InfoDisplay(prettyPrinter.writer, "[control: %s - %s] ", controlName, getControlURL(controlSummary.ID))
	if controlSummary.TotalResources == 0 {
		cautils.InfoDisplay(prettyPrinter.writer, "skipped %v\n", emoji.ConfusedFace)
	} else if controlSummary.TotalFailed != 0 {
		cautils.FailureDisplay(prettyPrinter.writer, "failed %v\n", emoji.SadButRelievedFace)
	} else if controlSummary.TotalWarning != 0 {
		cautils.WarningDisplay(prettyPrinter.writer, "excluded %v\n", emoji.NeutralFace)
	} else {
		cautils.SuccessDisplay(prettyPrinter.writer, "passed %v\n", emoji.ThumbsUp)
	}

	cautils.DescriptionDisplay(prettyPrinter.writer, "Description: %s\n", controlSummary.Description)

}
func (prettyPrinter *PrettyPrinter) printResources(controlSummary *ResultSummary) {

	if len(controlSummary.FailedWorkloads) > 0 {
		cautils.FailureDisplay(prettyPrinter.writer, "Failed:\n")
		prettyPrinter.printGroupedResources(controlSummary.FailedWorkloads)
	}
	if len(controlSummary.ExcludedWorkloads) > 0 {
		cautils.WarningDisplay(prettyPrinter.writer, "Excluded:\n")
		prettyPrinter.printGroupedResources(controlSummary.ExcludedWorkloads)
	}
	if len(controlSummary.PassedWorkloads) > 0 {
		cautils.SuccessDisplay(prettyPrinter.writer, "Passed:\n")
		prettyPrinter.printGroupedResources(controlSummary.PassedWorkloads)
	}

}

func (prettyPrinter *PrettyPrinter) printGroupedResources(workloads map[string][]WorkloadSummary) {
	indent := INDENT
	for title, rsc := range workloads {
		prettyPrinter.printGroupedResource(indent, title, rsc)
	}
}

func (prettyPrinter *PrettyPrinter) printGroupedResource(indent string, title string, rsc []WorkloadSummary) {
	preIndent := indent
	if title != "" {
		cautils.SimpleDisplay(prettyPrinter.writer, "%s%s\n", indent, title)
		indent += indent
	}

	for r := range rsc {
		relatedObjectsStr := generateRelatedObjectsStr(rsc[r])
		cautils.SimpleDisplay(prettyPrinter.writer, fmt.Sprintf("%s%s - %s %s\n", indent, rsc[r].resource.GetKind(), rsc[r].resource.GetName(), relatedObjectsStr))
	}
	indent = preIndent
}

func generateRelatedObjectsStr(workload WorkloadSummary) string {
	relatedStr := ""
	if workload.resource.GetObjectType() == workloadinterface.TypeWorkloadObject {
		relatedObjects := objectsenvelopes.NewRegoResponseVectorObject(workload.resource.GetObject()).GetRelatedObjects()
		for i, related := range relatedObjects {
			if ns := related.GetNamespace(); i == 0 && ns != "" {
				relatedStr += fmt.Sprintf("Namespace - %s, ", ns)
			}
			relatedStr += fmt.Sprintf("%s - %s, ", related.GetKind(), related.GetName())
		}
	}
	if relatedStr != "" {
		relatedStr = fmt.Sprintf(" [%s]", relatedStr[:len(relatedStr)-2])
	}
	return relatedStr
}

func generateRow(control string, cs ResultSummary) []string {
	row := []string{control}
	row = append(row, cs.ToSlice()...)
	if cs.TotalResources != 0 {
		row = append(row, fmt.Sprintf("%d", int(cs.RiskScore))+"%")
	} else {
		row = append(row, "skipped")
	}
	return row
}

func generateHeader() []string {
	return []string{"Control Name", "Failed Resources", "Excluded Resources", "All Resources", "% risk-score"}
}

func generateFooter(prettyPrinter *PrettyPrinter) []string {
	// Control name | # failed resources | all resources | % success
	row := []string{}
	row = append(row, "Resource Summary") //fmt.Sprintf(""%d", numControlers"))
	row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalFailed))
	row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalWarning))
	row = append(row, fmt.Sprintf("%d", prettyPrinter.frameworkSummary.TotalResources))
	row = append(row, fmt.Sprintf("%.2f%s", prettyPrinter.frameworkSummary.RiskScore, "%"))

	return row
}
func (prettyPrinter *PrettyPrinter) printSummaryTable(frameworksNames []string, frameworkScores []float32) {
	// For control scan framework will be nil
	prettyPrinter.printFramework(frameworksNames, frameworkScores)

	summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(generateHeader())
	summaryTable.SetHeaderLine(true)
	alignments := []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER}
	summaryTable.SetColumnAlignment(alignments)

	for i := 0; i < len(prettyPrinter.sortedControlNames); i++ {
		controlSummary := prettyPrinter.summary[prettyPrinter.sortedControlNames[i]]
		summaryTable.Append(generateRow(prettyPrinter.sortedControlNames[i], controlSummary))
	}

	summaryTable.SetFooter(generateFooter(prettyPrinter))

	// summaryTable.SetFooter(generateFooter())
	summaryTable.Render()
}

func (prettyPrinter *PrettyPrinter) printFramework(frameworksNames []string, frameworkScores []float32) {
	if len(frameworksNames) == 1 {
		if frameworksNames[0] != "" {
			cautils.InfoTextDisplay(prettyPrinter.writer, fmt.Sprintf("FRAMEWORK %s\n", frameworksNames[0]))
		}
	} else if len(frameworksNames) > 1 {
		p := "FRAMEWORKS: "
		for i := 0; i < len(frameworksNames)-1; i++ {
			p += fmt.Sprintf("%s (risk: %.2f), ", frameworksNames[i], frameworkScores[i])
		}
		p += fmt.Sprintf("%s (risk: %.2f)\n", frameworksNames[len(frameworksNames)-1], frameworkScores[len(frameworkScores)-1])
		cautils.InfoTextDisplay(prettyPrinter.writer, p)
	}
}

func (prettyPrinter *PrettyPrinter) getSortedControlsNames() []string {
	controlNames := make([]string, 0, len(prettyPrinter.summary))
	for k := range prettyPrinter.summary {
		controlNames = append(controlNames, k)
	}
	sort.Strings(controlNames)
	return controlNames
}
func getControlURL(controlID string) string {
	return fmt.Sprintf("https://hub.armo.cloud/docs/%s", strings.ToLower(controlID))
}
