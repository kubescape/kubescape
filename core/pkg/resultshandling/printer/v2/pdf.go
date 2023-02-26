package printer

import (
	"context"
	_ "embed"
	b64 "encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"

	"github.com/johnfercher/maroto/pkg/color"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
)

const (
	pdfOutputFile = "report"
	pdfOutputExt  = ".pdf"
)

var (
	//go:embed pdf/logo.png
	kubescapeLogo []byte
)

var _ printer.IPrinter = &PdfPrinter{}

type PdfPrinter struct {
	writer *os.File
}

func NewPdfPrinter() *PdfPrinter {
	return &PdfPrinter{}
}

func (pp *PdfPrinter) SetWriter(ctx context.Context, outputFile string) {
	// Ensure to have an available output file, otherwise create it.
	if strings.TrimSpace(outputFile) == "" {
		outputFile = pdfOutputFile
	}
	// Ensure to have the right file extension.
	if filepath.Ext(strings.TrimSpace(outputFile)) != pdfOutputExt {
		outputFile = outputFile + pdfOutputExt
	}
	pp.writer = printer.GetWriter(ctx, outputFile)
}

func (pp *PdfPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", cautils.Float32ToInt(score))
}
func (pp *PdfPrinter) printInfo(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails, infoMap []infoStars) {
	emptyRowCounter := 1
	for i := range infoMap {
		if infoMap[i].info != "" {
			m.Row(5, func() {
				m.Col(1, func() {
					m.Text(fmt.Sprintf("%v", infoMap[i].info))
				})
				m.Col(12, func() {
					m.Text(fmt.Sprintf("%v", infoMap[i].stars))
				})
			})
			if emptyRowCounter < len(infoMap) {
				m.Row(2.5, func() {})
				emptyRowCounter++
			}
		}
	}

}

func (pp *PdfPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj) {
	sortedControlIDs := getSortedControlsIDs(opaSessionObj.Report.SummaryDetails.Controls)

	infoToPrintInfo := mapInfoToPrintInfo(opaSessionObj.Report.SummaryDetails.Controls)
	m := pdf.NewMaroto(consts.Portrait, consts.A4)
	pp.printHeader(m)
	pp.printFramework(m, opaSessionObj.Report.SummaryDetails.ListFrameworks())
	pp.printTable(m, &opaSessionObj.Report.SummaryDetails, sortedControlIDs)
	pp.printFinalResult(m, &opaSessionObj.Report.SummaryDetails)
	pp.printInfo(m, &opaSessionObj.Report.SummaryDetails, infoToPrintInfo)

	// Extrat output buffer.
	outBuff, err := m.Output()
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to generate pdf format", helpers.Error(err))
		return
	}

	if _, err := pp.writer.Write(outBuff.Bytes()); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
	} else {
		printer.LogOutputFile(pp.writer.Name())
	}
}

// printHeader prints the Kubescape logo and report date
func (pp *PdfPrinter) printHeader(m pdf.Maroto) {
	// Retrieve current time (we need it for the report timestamp).
	t := time.Now()
	// Enconde PNG into Base64 to embed it into the pdf.
	kubescapeLogoEnc := b64.StdEncoding.EncodeToString(kubescapeLogo)

	m.SetPageMargins(10, 15, 10)
	m.Row(40, func() {
		//m.Text(fmt.Sprintf("Security Assessment"), props.Text{
		//	Align:  consts.Center,
		//	Size:   24,
		//	Family: consts.Arial,
		//	Style:  consts.Bold,
		//})
		_ = m.Base64Image(kubescapeLogoEnc, consts.Png, props.Rect{
			Center:  true,
			Percent: 100,
		})
	})
	m.Row(6, func() {
		m.Text(fmt.Sprintf("Report date: %d-%02d-%02dT%02d:%02d:%02d",
			t.Year(),
			t.Month(),
			t.Day(),
			t.Hour(),
			t.Minute(),
			t.Second()), props.Text{
			Align:  consts.Left,
			Size:   6.0,
			Style:  consts.Bold,
			Family: consts.Arial,
		})
	})
	m.Line(1)
}

// printFramework prints the PDF frameworks after the PDF header
func (pp *PdfPrinter) printFramework(m pdf.Maroto, frameworks []reportsummary.IFrameworkSummary) {
	m.Row(10, func() {
		m.Text(frameworksScoresToString(frameworks), props.Text{
			Align:  consts.Center,
			Size:   8,
			Family: consts.Arial,
			Style:  consts.Bold,
		})
	})
}

// printTable creates the PDF table
func (pp *PdfPrinter) printTable(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	headers := getControlTableHeaders()
	infoToPrintInfoMap := mapInfoToPrintInfo(summaryDetails.Controls)
	controls := make([][]string, len(sortedControlIDs))
	for i := range controls {
		controls[i] = make([]string, len(headers))
	}
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			controls[i] = generateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap, true)
		}
	}

	m.TableList(headers, controls, props.TableList{
		HeaderProp: props.TableListContent{
			Family: consts.Arial,
			Style:  consts.Bold,
			Size:   8.0,
		},
		ContentProp: props.TableListContent{
			Family: consts.Courier,
			Style:  consts.Normal,
			Size:   8.0,
		},
		Align: consts.Center,
		AlternatedBackground: &color.Color{
			Red:   224,
			Green: 224,
			Blue:  224,
		},
		HeaderContentSpace: 2.0,
		Line:               false,
	})
	m.Line(1)
	m.Row(2, func() {})
}

// printFinalResult adds the final results
func (pp *PdfPrinter) printFinalResult(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails) {
	m.Row(_rowLen, func() {
		m.Col(3, func() {
			m.Text("Resource summary", props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
		m.Col(2, func() {
			m.Text(fmt.Sprintf("%d", summaryDetails.NumberOfResources().Failed()), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
		m.Col(2, func() {
			m.Text(fmt.Sprintf("%d", summaryDetails.NumberOfResources().Skipped()), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
		m.Col(2, func() {
			m.Text(fmt.Sprintf("%d", summaryDetails.NumberOfResources().All()), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
		m.Col(2, func() {
			m.Text(fmt.Sprintf("%.2f%s", summaryDetails.Score, "%"), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
	})
}
