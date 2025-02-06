package pdf

import (
	_ "embed"
	"fmt"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/list"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/extension"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontfamily"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/consts/orientation"
	"github.com/johnfercher/maroto/v2/pkg/consts/pagesize"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

var (
	//go:embed logo.png
	kubescapeLogo []byte
)

type getTextColorFunc func(severity string) *props.Color

type Template struct {
	Maroto core.Maroto
}

// New Report Template is responsible for creating an object that generates a report with the submitted data
func NewReportTemplate() *Template {
	return &Template{
		Maroto: maroto.New(
			config.NewBuilder().
				WithPageSize(pagesize.A4).
				WithOrientation(orientation.Vertical).
				WithLeftMargin(10).
				WithTopMargin(15).
				WithRightMargin(10).
				Build()),
	}
}

// GetPdf is responsible for generating the pdf and returning the file's bytes
func (t *Template) GetPdf() ([]byte, error) {
	doc, err := t.Maroto.Generate()
	if err != nil {
		return nil, err
	}
	return doc.GetBytes(), nil
}

// printHeader prints the Kubescape logo, report date and framework
func (t *Template) GenerateHeader(scoreOfScannedFrameworks string) *Template {
	t.Maroto.AddRow(40, image.NewFromBytesCol(12, kubescapeLogo, extension.Png, props.Rect{
		Center:  true,
		Percent: 100,
	}))

	t.Maroto.AddRow(6, text.NewCol(12, fmt.Sprintf("Report date: %s", time.Now().Format(time.DateTime)),
		props.Text{
			Align:  align.Left,
			Size:   6.0,
			Style:  fontstyle.Bold,
			Family: fontfamily.Arial,
		}))

	t.Maroto.AddAutoRow(line.NewCol(12, props.Line{Thickness: 0.3, SizePercent: 100}))

	t.Maroto.AddRow(10, text.NewCol(12, scoreOfScannedFrameworks, props.Text{
		Align:  align.Center,
		Size:   8,
		Family: fontfamily.Arial,
		Style:  fontstyle.Bold,
	}))

	return t
}

// GenerateTable is responsible for adding data in table format to the pdf
func (t *Template) GenerateTable(getTextColor getTextColorFunc, tableRows *[]TableObject, totalFailed, total int, score float32) error {
	rows, err := list.Build[TableObject](*tableRows)
	if err != nil {
		return err
	}
	t.Maroto.AddRows(rows...)
	t.Maroto.AddRows(
		line.NewAutoRow(props.Line{Thickness: 0.3, SizePercent: 100}),
		row.New(2),
	)
	t.generateTableTableResult(totalFailed, total, score)

	return nil
}

// GenerateInfoRows is responsible for adding the information in pdf
func (t *Template) GenerateInfoRows(rows []string) *Template {
	for _, row := range rows {
		t.Maroto.AddAutoRow(text.NewCol(12, row, props.Text{
			Style: fontstyle.Bold,
			Align: align.Left,
			Top:   2.5,
			Size:  8,
			Color: &props.Color{
				Red:   0,
				Green: 0,
				Blue:  255,
			},
		}))
	}
	return t
}

func (t *Template) generateTableTableResult(totalFailed, total int, score float32) {
	defaultProps := props.Text{
		Align:  align.Left,
		Size:   8,
		Style:  fontstyle.Bold,
		Family: fontfamily.Arial,
	}

	t.Maroto.AddRow(10,
		text.NewCol(5, "Resource summary", defaultProps),
		text.NewCol(2, fmt.Sprintf("%d", totalFailed), defaultProps),
		text.NewCol(2, fmt.Sprintf("%d", total), defaultProps),
		text.NewCol(2, fmt.Sprintf("%.2f%s", score, "%"), defaultProps),
	)
}

// TableObject is responsible for mapping the table data, it will be sent to Maroto and will make it possible to generate the table
type TableObject struct {
	ref             string
	name            string
	counterFailed   string
	counterAll      string
	severity        string
	complianceScore string
	getTextColor    getTextColorFunc
}

func NewTableRow(ref, name, counterFailed, counterAll, severity, score string, getTextColor getTextColorFunc) *TableObject {
	return &TableObject{
		ref:             ref,
		name:            name,
		counterFailed:   counterFailed,
		counterAll:      counterAll,
		severity:        severity,
		complianceScore: score,
		getTextColor:    getTextColor,
	}
}

func (t TableObject) GetHeader() core.Row {
	return row.New(10).Add(
		text.NewCol(1, "Severity", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(1, "Control reference", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(6, "Control name", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(1, "Failed resources", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(1, "All resources", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(2, "Compliance score", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
	)
}

func (t TableObject) GetContent(i int) core.Row {
	r := row.New(3).Add(
		text.NewCol(1, t.severity, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: t.getTextColor(t.severity)}),
		text.NewCol(1, t.ref, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: &props.Color{}}),
		text.NewCol(6, t.name, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(1, t.counterFailed, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(1, t.counterAll, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(2, t.complianceScore, props.Text{VerticalPadding: 1, Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
	)

	if i%2 == 0 {
		r.WithStyle(&props.Cell{
			BackgroundColor: &props.Color{
				Red:   224,
				Green: 224,
				Blue:  224,
			},
		})
	}

	return r
}

func (t TableObject) getSeverityColor(severity string) *props.Color {
	if severity == "Critical" {
		return &props.Color{Red: 255, Green: 0, Blue: 0}
	} else if severity == "High" {
		return &props.Color{Red: 0, Green: 0, Blue: 255}
	} else if severity == "Medium" {
		return &props.Color{Red: 252, Green: 186, Blue: 3}
	}
	return &props.BlackColor
}
