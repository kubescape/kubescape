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

var (
	complianceFrameworks = []string{"nsa", "mitre"}
)

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
		cautils.SimpleDisplay(writer, "* %s: %.2f%%\n", fw.GetName(), fw.GetComplianceScore())
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

func ControlCountersForResource(l *helpersv1.AllLists) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, action required: %d)", l.Len(), l.Failed(), l.Skipped())
}

func getWorkloadPrefixForCmd(namespace, kind, name string) string {
	if namespace == "" {
		return fmt.Sprintf("name: %s, kind: %s", name, kind)
	}
	return fmt.Sprintf("namespace: %s, name: %s, kind: %s", namespace, name, kind)
}

func getCommonColumnsAlignments() []int {
	return []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
}

func printNextSteps(writer *os.File, nextSteps []string) {
	cautils.InfoTextDisplay(writer, "Follow-up steps:\n")
	for _, ns := range nextSteps {
		cautils.SimpleDisplay(writer, "- "+ns+"\n")
	}
}

func getTopWorkloadsTitle(topWLsLen int) string {
	if topWLsLen > 2 {
		return "Your most risky workloads:\n"
	}
	return "Your risky workloads:\n"
}
