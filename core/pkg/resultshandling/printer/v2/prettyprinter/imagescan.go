package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
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
		// filter out vulnerabilities with severity lower than High
		summary.CVEs = filterCVEsBySeverities(summary.CVEs, []string{apis.SeverityCriticalString, apis.SeverityHighString})
	}

	ip.imageTablePrinter.PrintImageScanningTable(ip.writer, summary)
	cautils.InfoTextDisplay(ip.writer, "\n")
}

func (ip *ImagePrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
}

func (ip *ImagePrinter) PrintNextSteps() {
	if ip.verboseMode {
		printNextSteps(ip.writer, []string{CICDSetupText, installHelmText, imagePatchText}, true)
		return
	}
	printNextSteps(ip.writer, []string{imageScanVerboseRunText, CICDSetupText, installHelmText, imagePatchText}, true)
}
