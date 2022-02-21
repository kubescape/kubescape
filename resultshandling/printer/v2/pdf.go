package v2

import (
	_ "embed"
	b64 "encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/johnfercher/maroto/pkg/color"
	"github.com/johnfercher/maroto/pkg/consts"
	"github.com/johnfercher/maroto/pkg/pdf"
	"github.com/johnfercher/maroto/pkg/props"
)

const (
	pdfOutputFile = "report"
	pdfOutputExt = ".pdf"
)

var (
	//go:embed pdf/logo.png
	kubescapeLogo []byte
)

type PdfPrinter struct {
	writer             *os.File
	sortedControlNames []string
}

func NewPdfPrinter() *PdfPrinter {
	return &PdfPrinter{}
}

func (pdfPrinter *PdfPrinter) SetWriter(outputFile string) {
	// Ensure to have an available output file, otherwise create it.
	if outputFile == "" {
		outputFile = pdfOutputFile
	}
	// Ensure to have the right file extension.
	if filepath.Ext(strings.TrimSpace(outputFile)) != pdfOutputExt {
		outputFile = outputFile + pdfOutputExt
	}
	pdfPrinter.writer = printer.GetWriter(outputFile)
}

func (pdfPrinter *PdfPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", int(score))
}

func (pdfPrinter *PdfPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	pdfPrinter.sortedControlNames = getSortedControlsNames(opaSessionObj.Report.SummaryDetails.Controls)

	m := pdf.NewMaroto(consts.Portrait, consts.A4)
	pdfPrinter.printHeader(m)
	pdfPrinter.printFramework(m, opaSessionObj.Report.SummaryDetails.ListFrameworks().All())
	pdfPrinter.printTable(m, &opaSessionObj.Report.SummaryDetails)
	pdfPrinter.printFinalResult(m, &opaSessionObj.Report.SummaryDetails)

	// Extrat output buffer.
	outBuff, err := m.Output()
	if err != nil {
		fmt.Println("Could not save PDF:", err)
		os.Exit(1)
	}
	pdfPrinter.writer.Write(outBuff.Bytes())
}

// Print Kubescape logo and report date.
func (pdfPrinter *PdfPrinter) printHeader(m pdf.Maroto) {
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

// Print pdf frameworks after pdf header.
func (pdfPrinter *PdfPrinter) printFramework(m pdf.Maroto, frameworks []reportsummary.IPolicies) {
	var p string
	if len(frameworks) == 1 {
		if frameworks[0].GetName() != "" {
			p = fmt.Sprintf("FRAMEWORK %s\n", frameworks[0].GetName())
		}
	} else if len(frameworks) > 1 {
		p = "FRAMEWORKS: "
		i := 0
		for ; i < len(frameworks)-1; i++ {
			p += fmt.Sprintf("%s (risk: %.2f), ", frameworks[i].GetName(), frameworks[i].GetScore())
		}
		p += fmt.Sprintf("%s (risk: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetScore())
	}
	m.Row(10, func() {
		m.Text(fmt.Sprintf(p), props.Text{
			Align:  consts.Center,
			Size:   8,
			Family: consts.Arial,
			Style:  consts.Bold,
		})
	})
}

// Create pdf table
func (pdfPrinter *PdfPrinter) printTable(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails) {
	headers := []string{"CONTROL NAME", "FAILED RESOURCES", "EXCLUDED RESOURCES", "ALL RESOURCES", "% RISK-SCORE"}

	controls := make([][]string, len(pdfPrinter.sortedControlNames))
	for i := range controls {
		controls[i] = make([]string, len(headers))
	}
	for i := 0; i < len(pdfPrinter.sortedControlNames); i++ {
		controls[i] = generateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaName, pdfPrinter.sortedControlNames[i]))
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
	m.Row(2, func(){})
}

// Add final results.
func (pdfPrinter *PdfPrinter) printFinalResult(m pdf.Maroto, summaryDetails *reportsummary.SummaryDetails) {
	m.Row(5, func() {
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
			m.Text(fmt.Sprintf("%d", summaryDetails.NumberOfResources().Excluded()), props.Text{
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

// Return sorted control names.
func getSortedControlsNames(controls reportsummary.ControlSummaries) []string {
	controlNames := make([]string, 0, len(controls))
	for k := range controls {
		c := controls[k]
		controlNames = append(controlNames, c.GetName())
	}
	sort.Strings(controlNames)
	return controlNames
}

// Generate rows to be appended to the table.
func generateRow(controlSummary reportsummary.IControlSummary) []string {
	// We use ReplaceAll because some control name
	// has a too long name that unformat the pdf view.
	controlName := strings.ReplaceAll(controlSummary.GetName(), "-", " ")
	row := []string{controlName}
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().Excluded()))
	row = append(row, fmt.Sprintf("%d", controlSummary.NumberOfResources().All()))

	if !controlSummary.GetStatus().IsSkipped() {
		row = append(row, fmt.Sprintf("%d", int(controlSummary.GetScore()))+"%")
	} else {
		row = append(row, "skipped")
	}
	return row
}
