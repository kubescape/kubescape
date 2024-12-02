package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
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

func (cp *ClusterPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, topWorkloadsByScore []reporthandling.IResource) {

	cp.categoriesTablePrinter.PrintCategoriesTables(cp.writer, summaryDetails, sortedControlIDs)

	if len(topWorkloadsByScore) > 0 {
		cp.printTopWorkloads(topWorkloadsByScore)
	}

	printComplianceScore(cp.writer, filterComplianceFrameworks(summaryDetails.ListFrameworks()))
}

func (cp *ClusterPrinter) PrintNextSteps() {
	printNextSteps(cp.writer, cp.getNextSteps(), true)
}

func (cp *ClusterPrinter) getNextSteps() []string {
	return []string{
		runCommandsText,
		scanWorkloadText,
		installKubescapeText,
	}
}

func (cp *ClusterPrinter) printTopWorkloads(topWorkloadsByScore []reporthandling.IResource) {
	txt := getTopWorkloadsTitle(len(topWorkloadsByScore))

	cautils.SectionHeadingDisplay(cp.writer, txt)
	cautils.SimpleDisplay(cp.writer, highStakesWlsText)

	for i, wl := range topWorkloadsByScore {
		ns := wl.GetNamespace()
		name := wl.GetName()
		kind := wl.GetKind()
		cautils.SimpleDisplay(cp.writer, fmt.Sprintf("%d. namespace: %s, name: %s, kind: %s\n", i+1, ns, name, kind))
		cautils.SimpleDisplay(cp.writer, fmt.Sprintf("   '%s'\n", getCallToActionString(cp.getWorkloadScanCommand(ns, kind, name))))
	}

	cautils.SimpleDisplay(cp.writer, "\n")
}

func (cp *ClusterPrinter) getWorkloadScanCommand(namespace, kind, name string) string {
	return fmt.Sprintf("$ kubescape scan workload %s/%s --namespace %s", kind, name, namespace)
}
