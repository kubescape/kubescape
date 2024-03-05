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
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
func (pp *PdfPrinter) printInfo(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails, infoMap []infoStars) {
	emptyRowCounter := 1
	for i := range infoMap {
		if infoMap[i].info != "" {
			m.Row(5, func() {
				m.Col(12, func() {
					m.Text(fmt.Sprintf("%v %v", infoMap[i].stars, infoMap[i].info), props.Text{
						Style:       consts.Bold,
						Align:       consts.Left,
						Size:        8,
						Extrapolate: false,
						Color: color.Color{
							Red:   0,
							Green: 0,
							Blue:  255,
						},
					})
				})
			})
			if emptyRowCounter < len(infoMap) {
				m.Row(2.5, func() {})
				emptyRowCounter++
			}
		}
	}

}

func (pp *PdfPrinter) PrintNextSteps() {

}

func (pp *PdfPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("failed to print results, missing data")
		return
	}

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
		return
	}
	printer.LogOutputFile(pp.writer.Name())
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
		m.Text(utils.FrameworksScoresToString(frameworks), props.Text{
			Align:  consts.Center,
			Size:   8,
			Family: consts.Arial,
			Style:  consts.Bold,
		})
	})
}

// printTable creates the PDF table
func (pp *PdfPrinter) printTable(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	headers := getControlTableHeaders(false)
	infoToPrintInfoMap := mapInfoToPrintInfo(summaryDetails.Controls)
	var controls [][]string
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := generateRowPdf(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap, true)
			if len(row) > 0 {
				controls = append(controls, row)
			}
		}
	}

	m.TableList(headers, controls, props.TableList{
		HeaderProp: props.TableListContent{
			Family:    consts.Arial,
			Style:     consts.Bold,
			Size:      6.0,
			GridSizes: []uint{1, 5, 2, 2, 2},
		},
		ContentProp: props.TableListContent{
			Family:                          consts.Courier,
			Style:                           consts.Normal,
			Size:                            6.0,
			GridSizes:                       []uint{1, 5, 2, 2, 2},
			CellTextColorChangerColumnIndex: 0,
			CellTextColorChangerFunc: func(cellValue string) color.Color {
				if cellValue == "Critical" {
					return color.Color{
						Red:   255,
						Green: 0,
						Blue:  0,
					}
				} else if cellValue == "High" {
					return color.Color{
						Red:   0,
						Green: 0,
						Blue:  255,
					}
				} else if cellValue == "Medium" {
					return color.Color{
						Red:   252,
						Green: 186,
						Blue:  3,
					}
				}
				return color.NewBlack()
			},
		},
		Align: consts.Left,
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
		m.Col(1, func() {
		})
		m.Col(5, func() {
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
			m.Text(fmt.Sprintf("%d", summaryDetails.NumberOfResources().All()), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
		m.Col(2, func() {
			m.Text(fmt.Sprintf("%.2f%s", summaryDetails.ComplianceScore, "%"), props.Text{
				Align:  consts.Left,
				Size:   8.0,
				Style:  consts.Bold,
				Family: consts.Arial,
			})
		})
	})
}
