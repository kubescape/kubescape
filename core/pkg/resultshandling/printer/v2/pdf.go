package printer

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/pdf"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	pdfOutputFile = "report"
	pdfOutputExt  = ".pdf"
)

var _ printer.IPrinter = &PdfPrinter{}

type PdfPrinter struct {
	writer *os.File
}

func NewPdfPrinter() *PdfPrinter {
	return &PdfPrinter{}
}

func (pp *PdfPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		// Ensure to have an available output file, otherwise create it.
		if strings.TrimSpace(outputFile) == "" {
			outputFile = pdfOutputFile
		}
		// Ensure to have the right file extension.
		if filepath.Ext(strings.TrimSpace(outputFile)) != pdfOutputExt {
			outputFile = outputFile + pdfOutputExt
		}
	}
	pp.writer = printer.GetWriter(ctx, outputFile)
}

func (pp *PdfPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))
}

func (pp *PdfPrinter) PrintNextSteps() {

}

// ActionPrint is responsible for generating a report in pdf format
func (pp *PdfPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("failed to print results, missing data")
		return
	}

	outBuff, err := pp.generatePdf(&opaSessionObj.Report.SummaryDetails)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to generate pdf format", helpers.Error(err))
		return
	}

	if _, err := pp.writer.Write(outBuff); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
		return
	}
	printer.LogOutputFile(pp.writer.Name())
}

func (pp *PdfPrinter) generatePdf(summaryDetails *reportsummary.SummaryDetails) ([]byte, error) {
	sortedControlIDs := getSortedControlsIDs(summaryDetails.Controls)
	infoToPrintInfo := mapInfoToPrintInfo(summaryDetails.Controls)

	template := pdf.NewReportTemplate()
	template.GenerateHeader(utils.FrameworksScoresToString(summaryDetails.ListFrameworks()))
	err := template.GenerateTable(getSeverityColor,
		pp.getTableObjects(summaryDetails, sortedControlIDs),
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

// getTableData is responsible for getting the table data in a standardized format
func (pp *PdfPrinter) getTableObjects(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) *[]pdf.TableObject {
	infoToPrintInfoMap := mapInfoToPrintInfo(summaryDetails.Controls)
	var controls []pdf.TableObject
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := generateTableRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap)
			controls = append(controls, *pdf.NewTableRow(
				row.ref, row.name, row.counterFailed, row.counterAll, row.severity, row.complianceScore, getSeverityColor,
			))
		}
	}
	return &controls
}

func getSeverityColor(severity string) *props.Color {
	if severity == "Critical" {
		return &props.Color{Red: 255, Green: 0, Blue: 0}
	} else if severity == "High" {
		return &props.Color{Red: 0, Green: 0, Blue: 255}
	} else if severity == "Medium" {
		return &props.Color{Red: 252, Green: 186, Blue: 3}
	}
	return &props.BlackColor
}
