package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	TopPackagesNumber = 5 // number of top packages to display
)

type ImagePrinter struct {
	writer            *os.File
	imageTablePrinter imageprinter.TablePrinter
	verboseMode       bool
}

func NewImagePrinter(writer *os.File, verboseMode bool) *ImagePrinter {
	return &ImagePrinter{
		writer:            writer,
		verboseMode:       verboseMode,
		imageTablePrinter: imageprinter.NewTableWriter(),
	}
}

var _ MainPrinter = &ImagePrinter{}

func (ip *ImagePrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	ip.PrintImageScanningTable(*summary)
	printImageScanningSummary(ip.writer, *summary, ip.verboseMode)
	printTopComponents(ip.writer, *summary)
}

func (ip *ImagePrinter) PrintImageScanningTable(summary imageprinter.ImageScanSummary) {
	if !ip.verboseMode {
		summary.CVEs = getFilteredCVEs(summary.CVEs)
	}

	ip.imageTablePrinter.PrintImageScanningTable(ip.writer, summary)
	cautils.SimpleDisplay(ip.writer, "\n")
}

func (ip *ImagePrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, topWorkloadsByScore []reporthandling.IResource) {
}

func (ip *ImagePrinter) PrintNextSteps() {
	if ip.verboseMode {
		printNextSteps(ip.writer, []string{installKubescapeText}, true)
		return
	}
	printNextSteps(ip.writer, []string{imageScanVerboseRunText, installKubescapeText}, true)
}
