package printer

import (
	"fmt"
	"os"
	"sort"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
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
	frameworkSummary   ControlSummary
}

func NewPrettyPrinter(verboseMode bool) *PrettyPrinter {
	return &PrettyPrinter{
		verboseMode: verboseMode,
		summary:     NewSummary(),
	}
}

func (printer *PrettyPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	// score := calculatePostureScore(opaSessionObj.PostureReport)
	failedResources := []string{}
	warningResources := []string{}
	allResources := []string{}
	frameworkNames := []string{}

	for _, frameworkReport := range opaSessionObj.PostureReport.FrameworkReports {
		frameworkNames = append(frameworkNames, frameworkReport.Name)
		failedResources = reporthandling.GetUniqueResourcesIDs(append(failedResources, frameworkReport.ListResourcesIDs().GetFailedResources()...))
		warningResources = reporthandling.GetUniqueResourcesIDs(append(warningResources, frameworkReport.ListResourcesIDs().GetWarningResources()...))
		allResources = reporthandling.GetUniqueResourcesIDs(append(allResources, frameworkReport.ListResourcesIDs().GetAllResources()...))
		printer.summarySetup(frameworkReport, opaSessionObj.AllResources)
	}

	printer.frameworkSummary = ControlSummary{
		TotalResources: len(allResources),
		TotalFailed:    len(failedResources),
		TotalWarning:   len(warningResources),
	}

	printer.printResults()
	printer.printSummaryTable(frameworkNames)

}

func (printer *PrettyPrinter) SetWriter(outputFile string) {
	printer.writer = getWriter(outputFile)
}

func (printer *PrettyPrinter) Score(score float32) {
}

func (printer *PrettyPrinter) summarySetup(fr reporthandling.FrameworkReport, allResources map[string]workloadinterface.IMetadata) {

	for _, cr := range fr.ControlReports {
		if len(cr.RuleReports) == 0 {
			continue
		}
		workloadsSummary := listResultSummary(cr.RuleReports, allResources)

		var passedWorkloads map[string][]WorkloadSummary
		if printer.verboseMode {
			passedWorkloads = groupByNamespaceOrKind(workloadsSummary, workloadSummaryPassed)
		}
		printer.summary[cr.Name] = ControlSummary{
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
	printer.sortedControlNames = printer.getSortedControlsNames()
}
func (printer *PrettyPrinter) printResults() {
	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummary := printer.summary[printer.sortedControlNames[i]]
		printer.printTitle(printer.sortedControlNames[i], &controlSummary)
		printer.printResources(&controlSummary)
		if printer.summary[printer.sortedControlNames[i]].TotalResources > 0 {
			printer.printSummary(printer.sortedControlNames[i], &controlSummary)
		}

	}
}

func (printer *PrettyPrinter) printSummary(controlName string, controlSummary *ControlSummary) {
	cautils.SimpleDisplay(printer.writer, "Summary - ")
	cautils.SuccessDisplay(printer.writer, "Passed:%v   ", controlSummary.TotalResources-controlSummary.TotalFailed-controlSummary.TotalWarning)
	cautils.WarningDisplay(printer.writer, "Excluded:%v   ", controlSummary.TotalWarning)
	cautils.FailureDisplay(printer.writer, "Failed:%v   ", controlSummary.TotalFailed)
	cautils.InfoDisplay(printer.writer, "Total:%v\n", controlSummary.TotalResources)
	if controlSummary.TotalFailed > 0 {
		cautils.DescriptionDisplay(printer.writer, "Remediation: %v\n", controlSummary.Remediation)
	}
	cautils.DescriptionDisplay(printer.writer, "\n")

}

func (printer *PrettyPrinter) printTitle(controlName string, controlSummary *ControlSummary) {
	cautils.InfoDisplay(printer.writer, "[control: %s] ", controlName)
	if controlSummary.TotalResources == 0 {
		cautils.InfoDisplay(printer.writer, "resources not found %v\n", emoji.ConfusedFace)
	} else if controlSummary.TotalFailed != 0 {
		cautils.FailureDisplay(printer.writer, "failed %v\n", emoji.SadButRelievedFace)
	} else if controlSummary.TotalWarning != 0 {
		cautils.WarningDisplay(printer.writer, "excluded %v\n", emoji.NeutralFace)
	} else {
		cautils.SuccessDisplay(printer.writer, "passed %v\n", emoji.ThumbsUp)
	}

	cautils.DescriptionDisplay(printer.writer, "Description: %s\n", controlSummary.Description)

}
func (printer *PrettyPrinter) printResources(controlSummary *ControlSummary) {

	if len(controlSummary.FailedWorkloads) > 0 {
		cautils.FailureDisplay(printer.writer, "Failed:\n")
		printer.printGroupedResources(controlSummary.FailedWorkloads)
	}
	if len(controlSummary.ExcludedWorkloads) > 0 {
		cautils.WarningDisplay(printer.writer, "Excluded:\n")
		printer.printGroupedResources(controlSummary.ExcludedWorkloads)
	}
	if len(controlSummary.PassedWorkloads) > 0 {
		cautils.SuccessDisplay(printer.writer, "Passed:\n")
		printer.printGroupedResources(controlSummary.PassedWorkloads)
	}

}

func (printer *PrettyPrinter) printGroupedResources(workloads map[string][]WorkloadSummary) {
	indent := INDENT
	for ns, rsc := range workloads {
		if !isKindToBeGrouped(ns) {
			printer.printGroupedResource(indent, ns, rsc)
		}
	}
	if rsc, ok := workloads["User"]; ok {
		printer.printGroupedResource(indent, "User", rsc)
	}
	if rsc, ok := workloads["Group"]; ok {
		printer.printGroupedResource(indent, "Group", rsc)
	}
	if rsc, ok := workloads["ClusterDescription"]; ok {
		printer.printGroupedResource(indent, "CloudProvider", rsc)
	}
}

func (printer *PrettyPrinter) printGroupedResource(indent string, ns string, rsc []WorkloadSummary) {
	preIndent := indent
	if isKindToBeGrouped(ns) {
		cautils.SimpleDisplay(printer.writer, "%s%ss\n", indent, ns)
	} else if ns != "" {
		cautils.SimpleDisplay(printer.writer, "%sNamespace %s\n", indent, ns)
	}
	preIndent2 := indent
	for r := range rsc {
		indent += indent
		relatedObjectsStr := generateRelatedObjectsStr(rsc[r])
		cautils.SimpleDisplay(printer.writer, fmt.Sprintf("%s%s - %s %s\n", indent, rsc[r].resource.GetKind(), rsc[r].resource.GetName(), relatedObjectsStr))
		indent = preIndent2
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
	row = append(row, "Resource Summary") //fmt.Sprintf(""%d", numControlers"))
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
func (printer *PrettyPrinter) printSummaryTable(frameworksNames []string) {
	// For control scan framework will be nil
	printer.printFramework(frameworksNames)

	summaryTable := tablewriter.NewWriter(printer.writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(generateHeader())
	summaryTable.SetHeaderLine(true)
	alignments := []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER}
	summaryTable.SetColumnAlignment(alignments)

	for i := 0; i < len(printer.sortedControlNames); i++ {
		controlSummary := printer.summary[printer.sortedControlNames[i]]
		summaryTable.Append(generateRow(printer.sortedControlNames[i], controlSummary))
	}
	summaryTable.SetFooter(generateFooter(len(printer.summary), printer.frameworkSummary.TotalFailed, printer.frameworkSummary.TotalWarning, printer.frameworkSummary.TotalResources))
	summaryTable.Render()
}

func (printer *PrettyPrinter) printFramework(frameworksNames []string) {
	if len(frameworksNames) == 1 {
		cautils.InfoTextDisplay(printer.writer, fmt.Sprintf("%s FRAMEWORK\n", frameworksNames[0]))
	} else if len(frameworksNames) > 1 {
		p := ""
		for i := 0; i < len(frameworksNames)-1; i++ {
			p += frameworksNames[i] + ", "
		}
		p += frameworksNames[len(frameworksNames)-1]
		cautils.InfoTextDisplay(printer.writer, fmt.Sprintf("%s FRAMEWORKS\n", p))
	}
}

func (printer *PrettyPrinter) getSortedControlsNames() []string {
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
			fmt.Println("failed to open file for writing, reason: ", err.Error())
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}
