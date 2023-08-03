package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type RepoPrinter struct {
	writer                 *os.File
	inputPatterns          []string
	categoriesTablePrinter configurationprinter.TablePrinter
}

func NewRepoPrinter(writer *os.File, inputPatterns []string) *RepoPrinter {
	return &RepoPrinter{
		writer:                 writer,
		categoriesTablePrinter: configurationprinter.NewRepoPrinter(inputPatterns),
	}
}

var _ MainPrinter = &RepoPrinter{}

func (rp *RepoPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	printImageScanningSummary(rp.writer, *summary, false)
	printImagesCommands(rp.writer, *summary)
	printTopComponents(rp.writer, *summary)
}

func (rp *RepoPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	rp.categoriesTablePrinter.PrintCategoriesTables(rp.writer, summaryDetails, sortedControlIDs)

	if len(summaryDetails.TopWorkloadsByScore) > 1 {
		rp.printTopWorkloads(summaryDetails)
	}

}

func (rp *RepoPrinter) PrintNextSteps() {
	printNextSteps(rp.writer, rp.getNextSteps(), false)
}

func (rp *RepoPrinter) getNextSteps() []string {
	return []string{
		configScanVerboseRunText,
		clusterScanRunText,
		CICDSetupText,
		installHelmText,
	}
}

func (rp *RepoPrinter) printTopWorkloads(summaryDetails *reportsummary.SummaryDetails) {
	cautils.InfoTextDisplay(rp.writer, getTopWorkloadsTitle(len(summaryDetails.TopWorkloadsByScore)))

	for i, wl := range summaryDetails.TopWorkloadsByScore {
		ns := wl.GetNamespace()
		name := wl.GetName()
		kind := wl.GetKind()
		cmdPrefix := getWorkloadPrefixForCmd(ns, kind, name)
		cautils.SimpleDisplay(rp.writer, fmt.Sprintf("%d. %s - '%s'\n", i+1, cmdPrefix, getCallToActionString(rp.getWorkloadScanCommand(ns, kind, name, *wl.GetSource()))))
	}

	cautils.InfoTextDisplay(rp.writer, "\n")
}

func (rp *RepoPrinter) getWorkloadScanCommand(ns, kind, name string, source reporthandling.Source) string {
	cmd := fmt.Sprintf("$ kubescape scan workload %s/%s --namespace %s", kind, name, ns)
	if ns == "" {
		cmd = fmt.Sprintf("$ kubescape scan workload %s/%s", kind, name)
	}

	if source.FileType == reporthandling.SourceTypeHelmChart {
		return fmt.Sprintf("%s --chart-path=%s --file-path=%s", cmd, source.HelmPath, fmt.Sprintf("%s/%s", source.Path, source.RelativePath))

	} else {
		return fmt.Sprintf("%s --file-path=%s", cmd, fmt.Sprintf("%s/%s", source.Path, source.RelativePath))
	}
}
