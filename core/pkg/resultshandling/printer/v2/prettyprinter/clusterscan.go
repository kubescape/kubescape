package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type ClusterPrinter struct {
	writer                 *os.File
	categoriesTablePrinter configurationprinter.TablePrinter
}

func NewClusterPrinter(writer *os.File) *ClusterPrinter {
	return &ClusterPrinter{
		writer:                 writer,
		categoriesTablePrinter: configurationprinter.NewClusterPrinter(),
	}
}

var _ MainPrinter = &ClusterPrinter{}

func (cp *ClusterPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	printImageScanningSummary(cp.writer, *summary, false)
	printImagesCommands(cp.writer, *summary)
}

func (cp *ClusterPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

	cp.categoriesTablePrinter.PrintCategoriesTables(cp.writer, summaryDetails, sortedControlIDs)

	printComplianceScore(cp.writer, filterComplianceFrameworks(summaryDetails.ListFrameworks()))

	if len(summaryDetails.TopWorkloadsByScore) > 0 {
		cp.printTopWorkloads(summaryDetails)
	}

}

func (cp *ClusterPrinter) PrintNextSteps() {
	printNextSteps(cp.writer, cp.getNextSteps())
}

func (cp *ClusterPrinter) getNextSteps() []string {
	return []string{
		configScanVerboseRunText,
		installHelmText,
	}
}

func (cp *ClusterPrinter) printTopWorkloads(summaryDetails *reportsummary.SummaryDetails) {
	cautils.InfoTextDisplay(cp.writer, getTopWorkloadsTitle(len(summaryDetails.TopWorkloadsByScore)))

	for i, wl := range summaryDetails.TopWorkloadsByScore {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cautils.SimpleDisplay(cp.writer, fmt.Sprintf("%d. namespace: %s, name: %s, kind: %s - '%s'\n", i+1, ns, name, kind, cp.getWorkloadScanCommand(ns, kind, name)))
	}

	cautils.SimpleDisplay(cp.writer, "Read more about the most risky workloads here: https://docs.io/most-risky-workloads\n")

	cautils.InfoTextDisplay(cp.writer, "\n")
}

func (cp *ClusterPrinter) getWorkloadScanCommand(namespace, kind, name string) string {
	return fmt.Sprintf("$ kubescape scan workload %s/%s --namespace %s", kind, name, namespace)
}
