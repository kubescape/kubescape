package prettyprinter

import (
	"fmt"
	"os"
	"strings"

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

func (rp *RepoPrinter) PrintImageScanning(*imageprinter.ImageScanSummary) {
}

func (rp *RepoPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	rp.categoriesTablePrinter.PrintCategoriesTable(rp.writer, summaryDetails, sortedControlIDs)

	if len(summaryDetails.TopWorkloadsByScore) > 0 {
		rp.printTopWorkloads(summaryDetails)
	}

}

func (rp *RepoPrinter) PrintNextSteps() {
	printNextSteps(rp.writer, rp.getNextSteps())

}

func (rp *RepoPrinter) getNextSteps() []string {
	return []string{
		clusterScanRunText,
		CICDSetupText,
		installHelmText,
	}
}

func (rp *RepoPrinter) printNextSteps() {
	printNextSteps(rp.writer, rp.getNextSteps())
}

func (rp *RepoPrinter) printTopWorkloads(summaryDetails *reportsummary.SummaryDetails) {
	cautils.InfoTextDisplay(rp.writer, getTopWorkloadsTitle(len(summaryDetails.TopWorkloadsByScore)))

	for i, wl := range summaryDetails.TopWorkloadsByScore {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cmdPrefix := getWorkloadPrefixForCmd(ns, kind, name)
		cautils.SimpleDisplay(rp.writer, fmt.Sprintf("%d. %s - '%s'\n", i+1, cmdPrefix, rp.getWorkloadScanCommand(ns, kind, name, wl.ResourceSource)))
	}

	cautils.InfoTextDisplay(rp.writer, "\n")
}

func (rp *RepoPrinter) getWorkloadScanCommand(ns, kind, name string, source reporthandling.Source) string {
	cmd := fmt.Sprintf("$ kubescape scan workload %s/%s/%s", ns, kind, name)
	if ns == "" {
		cmd = fmt.Sprintf("$ kubescape scan workload %s/%s", kind, name)
	}
	if source.FileType == "Helm" {
		return fmt.Sprintf("%s --chart-path=%s", cmd, source.RelativePath)

	} else {
		return fmt.Sprintf("%s --file-path=%s", cmd, source.RelativePath)
	}
}

func (rp *RepoPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary, inputPatterns []string) string {
	return fmt.Sprintf("$ kubescape scan control %s %s", controlSummary.GetID(), strings.Join(inputPatterns, ","))
}
