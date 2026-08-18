package printer

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/pdf"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	pdfOutputFile = "report"
)

var _ printer.IPrinter = &PdfPrinter{}

type PdfPrinter struct {
	writer *os.File
}

func NewPdfPrinter() *PdfPrinter {
	return &PdfPrinter{}
}

func (pp *PdfPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		// Binary PDF must never fall back to stdout: it corrupts TTYs and
		// is rarely what the user intended. Default to ./report.pdf.
		outputFile = pdfOutputFile + printer.PdfOutputExt
		logger.L().Info("no --output specified for pdf format; writing to default file",
			helpers.String("filename", outputFile))
	} else if filepath.Ext(outputFile) != printer.PdfOutputExt {
		outputFile = outputFile + printer.PdfOutputExt
	}
	if explicitOutput {
		var err error
		pp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	// The implicit PDF destination must never fall back to stdout. Preserve
	// the existing temp-file fallback if the default path cannot be opened.
	pp.writer = printer.GetWriterNoStdoutFallback(ctx, outputFile, "kubescape-report-*"+printer.PdfOutputExt)
	return nil
}

func (pp *PdfPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

func (pp *PdfPrinter) PrintNextSteps() {

}

// ActionPrint is responsible for generating a report in pdf format
func (pp *PdfPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	var outBuff []byte
	var err error

	if opaSessionObj != nil {
		outBuff, err = pp.generatePdf(&opaSessionObj.Report.SummaryDetails)
	} else if len(imageScanData) > 0 {
		outBuff, err = pp.generateImagePdf(imageScanData)
	} else {
		return fmt.Errorf("failed to print results, missing data")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to generate pdf format", helpers.Error(err))
		return fmt.Errorf("failed to generate pdf format: %w", err)
	}

	if _, err := pp.writer.Write(outBuff); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
		return fmt.Errorf("failed to write results: %w", err)
	}
	printer.LogOutputFile(pp.writer.Name())
	return nil
}

// generateImagePdf builds a CVE-table PDF report for an image scan (#2782)
func (pp *PdfPrinter) generateImagePdf(imageScanData []cautils.ImageScanData) ([]byte, error) {
	var allCVEs []imageprinter.CVE
	var images []string
	for i := range imageScanData {
		allCVEs = append(allCVEs, extractCVEs(imageScanData[i].Matches, imageScanData[i].Image)...)
		images = append(images, imageScanData[i].Image)
	}

	template := pdf.NewReportTemplate()
	template.GenerateHeader(fmt.Sprintf("Image scan: %s", strings.Join(images, ", ")), time.Now().Format(time.DateTime))

	rows, fixableCVEs := pp.getImageTableObjects(allCVEs)
	if err := template.GenerateImageTable(rows, len(allCVEs), fixableCVEs); err != nil {
		return nil, err
	}

	return template.GetPdf()
}

// getImageTableObjects converts CVEs into PDF table rows, returning the rows and how many are fixable
func (pp *PdfPrinter) getImageTableObjects(cves []imageprinter.CVE) (*[]pdf.ImageTableObject, int) {
	if len(cves) == 0 {
		// maroto's list.Build returns errors.New("empty array") for an
		// empty slice, so a clean image (zero CVEs) previously produced
		// no PDF at all — the exact case a pipeline expects to succeed.
		// A single placeholder row keeps the table non-empty and tells
		// the reader the scan was clean, instead of failing silently.
		rows := []pdf.ImageTableObject{
			*pdf.NewImageTableRow("—", "—", "—", "None", "No vulnerabilities found", getSeverityColor),
		}
		return &rows, 0
	}

	rows := make([]pdf.ImageTableObject, 0, len(cves))
	fixableCVEs := 0
	for _, cve := range cves {
		fixVersions := "no fix available"
		if len(cve.FixVersions) > 0 {
			fixVersions = strings.Join(cve.FixVersions, ", ")
			fixableCVEs++
		}
		rows = append(rows, *pdf.NewImageTableRow(cve.ID, cve.Package, cve.Version, cve.Severity, fixVersions, getSeverityColor))
	}
	return &rows, fixableCVEs
}

func (pp *PdfPrinter) generatePdf(summaryDetails *reportsummary.SummaryDetails) ([]byte, error) {
	sortedControlIDs := getSortedControlsIDs(summaryDetails.Controls)
	infoToPrintInfo := mapInfoToPrintInfo(summaryDetails.Controls)

	template := pdf.NewReportTemplate()
	template.GenerateHeader(utils.FrameworksScoresToString(summaryDetails.ListFrameworks()), time.Now().Format(time.DateTime))
	err := template.GenerateTable(pp.getTableObjects(summaryDetails, sortedControlIDs, infoToPrintInfo),
		summaryDetails.NumberOfResources().Failed(), summaryDetails.NumberOfResources().All(), summaryDetails.ComplianceScore)

	if err != nil {
		return nil, err
	}
	template.GenerateInfoRows(pp.getFormattedInformation(infoToPrintInfo))
	return template.GetPdf()
}

func (pp *PdfPrinter) getFormattedInformation(infoMap []infoStars) []string {
	rows := make([]string, 0, len(infoMap))
	for i := range infoMap {
		if infoMap[i].info != "" {
			rows = append(rows, fmt.Sprintf("%v %v", infoMap[i].stars, infoMap[i].info))
		}
	}
	return rows
}

// getTableData is responsible for getting the table data in a standardized format.
// The markers are taken from the caller so the table and the legend share one list.
func (pp *PdfPrinter) getTableObjects(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, infoToPrintInfoMap []infoStars) *[]pdf.TableObject {
	var controls []pdf.TableObject
	for _, sortedControlID := range slices.Backward(sortedControlIDs) {
		for _, c := range sortedControlID {
			row := generateTableRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap)
			controls = append(controls, *pdf.NewTableRow(
				row.ref, row.name, row.counterFailed, row.counterAll, row.severity, row.complianceScore, getSeverityColor,
			))
		}
	}
	return &controls
}

func getSeverityColor(severity string) *props.Color {
	switch severity {
	case "Critical":
		return &props.Color{Red: 255, Green: 0, Blue: 0}
	case "High":
		return &props.Color{Red: 0, Green: 0, Blue: 255}
	case "Medium":
		return &props.Color{Red: 252, Green: 186, Blue: 3}
	}
	return &props.BlackColor
}

// CloseWriter closes the PDF output writer, returning any error from flushing or closing.
func (p *PdfPrinter) CloseWriter() error {
	if p.writer != nil && p.writer != os.Stdout {
		return p.writer.Close()
	}
	return nil
}
