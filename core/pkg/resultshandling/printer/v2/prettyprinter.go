package v2

import (
	"fmt"
	"os"
	"sort"

	"github.com/enescakir/emoji"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

type PrettyPrinter struct {
	formatVersion string
	viewType      cautils.ViewTypes
	writer        *os.File
	verboseMode   bool
}

func NewPrettyPrinter(verboseMode bool, formatVersion string, viewType cautils.ViewTypes) *PrettyPrinter {
	return &PrettyPrinter{
		verboseMode:   verboseMode,
		formatVersion: formatVersion,
		viewType:      viewType,
	}
}

func (prettyPrinter *PrettyPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	fmt.Fprintf(prettyPrinter.writer, "\n"+getSeparator("^")+"\n")

	sortedControlNames := getSortedControlsNames(opaSessionObj.Report.SummaryDetails.Controls) // ListControls().All())

	switch prettyPrinter.viewType {
	case cautils.ControlViewType:
		prettyPrinter.printResults(&opaSessionObj.Report.SummaryDetails.Controls, opaSessionObj.AllResources, sortedControlNames)
	case cautils.ResourceViewType:
		if prettyPrinter.verboseMode {
			prettyPrinter.resourceTable(opaSessionObj)
		}
	}

	prettyPrinter.printSummaryTable(&opaSessionObj.Report.SummaryDetails, sortedControlNames)

}

func (prettyPrinter *PrettyPrinter) SetWriter(outputFile string) {
	prettyPrinter.writer = printer.GetWriter(outputFile)
}

func (prettyPrinter *PrettyPrinter) Score(score float32) {
}

func (prettyPrinter *PrettyPrinter) printResults(controls *reportsummary.ControlSummaries, allResources map[string]workloadinterface.IMetadata, sortedControlNames [][]string) {
	for i := len(sortedControlNames) - 1; i >= 0; i-- {
		for _, c := range sortedControlNames[i] {
			controlSummary := controls.GetControl(reportsummary.EControlCriteriaName, c) //  summaryDetails.Controls ListControls().All() Controls.GetControl(ca)
			prettyPrinter.printTitle(controlSummary)
			prettyPrinter.printResources(controlSummary, allResources)
			prettyPrinter.printSummary(c, controlSummary)
		}
	}
}

func (prettyPrinter *PrettyPrinter) printSummary(controlName string, controlSummary reportsummary.IControlSummary) {
	if controlSummary.GetStatus().IsSkipped() {
		return
	}
	cautils.SimpleDisplay(prettyPrinter.writer, "Summary - ")
	cautils.SuccessDisplay(prettyPrinter.writer, "Passed:%v   ", controlSummary.NumberOfResources().Passed())
	cautils.WarningDisplay(prettyPrinter.writer, "Excluded:%v   ", controlSummary.NumberOfResources().Excluded())
	cautils.FailureDisplay(prettyPrinter.writer, "Failed:%v   ", controlSummary.NumberOfResources().Failed())
	cautils.InfoDisplay(prettyPrinter.writer, "Total:%v\n", controlSummary.NumberOfResources().All())
	if controlSummary.GetStatus().IsFailed() {
		cautils.DescriptionDisplay(prettyPrinter.writer, "Remediation: %v\n", controlSummary.GetRemediation())
	}
	cautils.DescriptionDisplay(prettyPrinter.writer, "\n")

}
func (prettyPrinter *PrettyPrinter) printTitle(controlSummary reportsummary.IControlSummary) {
	cautils.InfoDisplay(prettyPrinter.writer, "[control: %s - %s] ", controlSummary.GetName(), cautils.GetControlLink(controlSummary.GetID()))
	switch controlSummary.GetStatus().Status() {
	case apis.StatusSkipped:
		cautils.InfoDisplay(prettyPrinter.writer, "skipped %v\n", emoji.ConfusedFace)
	case apis.StatusFailed:
		cautils.FailureDisplay(prettyPrinter.writer, "failed %v\n", emoji.SadButRelievedFace)
	case apis.StatusExcluded:
		cautils.WarningDisplay(prettyPrinter.writer, "excluded %v\n", emoji.NeutralFace)
	case apis.StatusIrrelevant:
		cautils.SuccessDisplay(prettyPrinter.writer, "irrelevant %v\n", emoji.ConfusedFace)
	case apis.StatusError:
		cautils.WarningDisplay(prettyPrinter.writer, "error %v\n", emoji.ConfusedFace)
	default:
		cautils.SuccessDisplay(prettyPrinter.writer, "passed %v\n", emoji.ThumbsUp)
	}
	cautils.DescriptionDisplay(prettyPrinter.writer, "Description: %s\n", controlSummary.GetDescription())
	if controlSummary.GetStatus().Info() != "" {
		cautils.WarningDisplay(prettyPrinter.writer, "Reason: %v\n", controlSummary.GetStatus().Info())
	}
}
func (prettyPrinter *PrettyPrinter) printResources(controlSummary reportsummary.IControlSummary, allResources map[string]workloadinterface.IMetadata) {

	workloadsSummary := listResultSummary(controlSummary, allResources)

	failedWorkloads := groupByNamespaceOrKind(workloadsSummary, workloadSummaryFailed)
	excludedWorkloads := groupByNamespaceOrKind(workloadsSummary, workloadSummaryExclude)

	var passedWorkloads map[string][]WorkloadSummary
	if prettyPrinter.verboseMode {
		passedWorkloads = groupByNamespaceOrKind(workloadsSummary, workloadSummaryPassed)
	}
	if len(failedWorkloads) > 0 {
		cautils.FailureDisplay(prettyPrinter.writer, "Failed:\n")
		prettyPrinter.printGroupedResources(failedWorkloads)
	}
	if len(excludedWorkloads) > 0 {
		cautils.WarningDisplay(prettyPrinter.writer, "Excluded:\n")
		prettyPrinter.printGroupedResources(excludedWorkloads)
	}
	if len(passedWorkloads) > 0 {
		cautils.SuccessDisplay(prettyPrinter.writer, "Passed:\n")
		prettyPrinter.printGroupedResources(passedWorkloads)
	}

}

func (prettyPrinter *PrettyPrinter) printGroupedResources(workloads map[string][]WorkloadSummary) {
	indent := "  "
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

	resources := []string{}
	for r := range rsc {
		relatedObjectsStr := generateRelatedObjectsStr(rsc[r]) // TODO -
		resources = append(resources, fmt.Sprintf("%s%s - %s %s", indent, rsc[r].resource.GetKind(), rsc[r].resource.GetName(), relatedObjectsStr))
	}

	sort.Strings(resources)
	for i := range resources {
		cautils.SimpleDisplay(prettyPrinter.writer, resources[i]+"\n")
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
func generateFooter(summaryDetails *reportsummary.SummaryDetails) []string {
	// Control name | # failed resources | all resources | % success
	row := make([]string, _rowLen)
	row[columnName] = "Resource Summary"
	row[columnCounterFailed] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed())
	row[columnCounterExclude] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().Excluded())
	row[columnCounterAll] = fmt.Sprintf("%d", summaryDetails.NumberOfResources().All())
	row[columnSeverity] = " "
	row[columnRiskScore] = fmt.Sprintf("%.2f%s", summaryDetails.Score, "%")

	return row
}
func (prettyPrinter *PrettyPrinter) printSummaryTable(summaryDetails *reportsummary.SummaryDetails, sortedControlNames [][]string) {

	if summaryDetails.NumberOfControls().All() == 0 {
		fmt.Fprintf(prettyPrinter.writer, "\nKubescape did not scan any of the resources, make sure you are scanning valid kubernetes manifests (Deployments, Pods, etc.)\n")
		return
	}
	cautils.InfoTextDisplay(prettyPrinter.writer, "\n"+controlCountersForSummary(summaryDetails.NumberOfControls())+"\n")
	cautils.InfoTextDisplay(prettyPrinter.writer, renderSeverityCountersSummary(&summaryDetails.SeverityCounters)+"\n\n")

	// cautils.InfoTextDisplay(prettyPrinter.writer, "\n"+"Severities: SOME OTHER"+"\n\n")

	summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(getControlTableHeaders())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetColumnAlignment(getColumnsAlignments())

	printAll := prettyPrinter.verboseMode
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	infoToPrintInfo := mapInfoToPrintInfo(summaryDetails.Controls)
	for i := len(sortedControlNames) - 1; i >= 0; i-- {
		for _, c := range sortedControlNames[i] {
			row := generateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaName, c), infoToPrintInfo, printAll)
			if len(row) > 0 {
				summaryTable.Append(row)
			}
		}
	}

	summaryTable.SetFooter(generateFooter(summaryDetails))

	summaryTable.Render()

	// When scanning controls the framework list will be empty
	cautils.InfoTextDisplay(prettyPrinter.writer, frameworksScoresToString(summaryDetails.ListFrameworks()))

	prettyPrinter.printInfo(infoToPrintInfo)

}

func (prettyPrinter *PrettyPrinter) printInfo(infoToPrintInfo []infoStars) {
	fmt.Println()
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(prettyPrinter.writer, fmt.Sprintf("%s %s\n", infoToPrintInfo[i].stars, infoToPrintInfo[i].info))
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
			p += fmt.Sprintf("%s (risk: %.2f), ", frameworks[i].GetName(), frameworks[i].GetScore())
		}
		p += fmt.Sprintf("%s (risk: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetScore())
		return p
	}
	return ""
}

// renderSeverityCountersSummary renders the string that reports severity counters summary
func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) string {
	critical := counters.NumberOfResourcesWithCriticalSeverity()
	high := counters.NumberOfResourcesWithHighSeverity()
	medium := counters.NumberOfResourcesWithMediumSeverity()
	low := counters.NumberOfResourcesWithLowSeverity()

	return fmt.Sprintf(
		"Failed Resources by Severity: Critical — %d, High — %d, Medium — %d, Low — %d",
		critical, high, medium, low,
	)
}

func controlCountersForSummary(counters reportsummary.ICounters) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Excluded: %d, Skipped: %d)", counters.All(), counters.Failed(), counters.Excluded(), counters.Skipped())
}

func controlCountersForResource(l *helpersv1.AllLists) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Excluded: %d)", l.All().Len(), len(l.Failed()), len(l.Excluded()))
}
func getSeparator(sep string) string {
	s := ""
	for i := 0; i < 80; i++ {
		s += sep
	}
	return s
}
