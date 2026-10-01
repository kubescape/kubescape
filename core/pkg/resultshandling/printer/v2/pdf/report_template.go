package pdf

import (
	_ "embed"
	"fmt"

	"github.com/johnfercher/go-tree/node"
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
	"github.com/kubescape/kubescape/v4/core/cautils"
)

var (
	//go:embed logo.png
	kubescapeLogo []byte
)

type getTextColorFunc func(severity string) *props.Color

type Template struct {
	maroto core.Maroto
}

// New Report Template is responsible for creating an object that generates a report with the submitted data
func NewReportTemplate() *Template {
	return &Template{
		maroto: maroto.New(
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
	doc, err := t.maroto.Generate()
	if err != nil {
		return nil, err
	}
	return doc.GetBytes(), nil
}

// printHeader prints the Kubescape logo, report date and framework
func (t *Template) GenerateHeader(scoreOfScannedFrameworks, reportDate string) *Template {
	t.maroto.AddRow(40, image.NewFromBytesCol(12, kubescapeLogo, extension.Png, props.Rect{
		Center:  true,
		Percent: 100,
	}))

	t.maroto.AddRow(6, text.NewCol(12, fmt.Sprintf("Report date: %s", reportDate),
		props.Text{
			Align:  align.Left,
			Size:   6.0,
			Style:  fontstyle.Bold,
			Family: fontfamily.Arial,
		}))

	t.maroto.AddAutoRow(line.NewCol(12, props.Line{Thickness: 0.3, SizePercent: 100}))

	t.maroto.AddRow(10, text.NewCol(12, scoreOfScannedFrameworks, props.Text{
		Align:  align.Center,
		Size:   8,
		Family: fontfamily.Arial,
		Style:  fontstyle.Bold,
	}))

	return t
}

// GenerateTable is responsible for adding data in table format to the pdf
func (t *Template) GenerateTable(tableRows *[]TableObject, totalFailed, total int, score float32) error {
	rows, err := list.Build[TableObject](*tableRows)
	if err != nil {
		return err
	}
	t.maroto.AddRows(rows...)
	t.maroto.AddRows(
		line.NewAutoRow(props.Line{Thickness: 0.3, SizePercent: 100}),
		row.New(2),
	)
	t.generateTableTableResult(totalFailed, total, score)

	return nil
}

// GenerateSectionTitle adds a heading for a later section of the same document.
func (t *Template) GenerateSectionTitle(title string) *Template {
	t.maroto.AddRow(10, text.NewCol(12, title, props.Text{
		Align:  align.Left,
		Size:   8,
		Family: fontfamily.Arial,
		Style:  fontstyle.Bold,
	}))
	return t
}

// GenerateImageTable is responsible for adding CVE data in table format to the pdf for an image scan (#2782)
func (t *Template) GenerateImageTable(tableRows *[]ImageTableObject, totalCVEs, fixableCVEs int) error {
	rows, err := list.Build[ImageTableObject](*tableRows)
	if err != nil {
		return err
	}
	t.maroto.AddRows(rows...)
	t.maroto.AddRows(
		line.NewAutoRow(props.Line{Thickness: 0.3, SizePercent: 100}),
		row.New(2),
	)
	t.generateImageTableResult(totalCVEs, fixableCVEs)

	return nil
}

func (t *Template) generateImageTableResult(totalCVEs, fixableCVEs int) {
	defaultProps := props.Text{
		Align:  align.Left,
		Size:   8,
		Style:  fontstyle.Bold,
		Family: fontfamily.Arial,
	}

	t.maroto.AddRow(10,
		text.NewCol(6, "Vulnerability summary", defaultProps),
		text.NewCol(3, fmt.Sprintf("%d CVEs", totalCVEs), defaultProps),
		text.NewCol(3, fmt.Sprintf("%d fixable", fixableCVEs), defaultProps),
	)
}

// GenerateCoverageSummaryRow adds a scan coverage summary row below the resource summary,
// and surfaces unexamined resource kind diagnostics when present (#3884, #3958).
func (t *Template) GenerateCoverageSummaryRow(evaluated, total int, score float32, degraded bool, unexaminedKinds []cautils.UnexaminedKind) {
	defaultProps := props.Text{
		Align:  align.Left,
		Size:   8,
		Style:  fontstyle.Bold,
		Family: fontfamily.Arial,
	}

	scoreText := cautils.ComplianceScoreToString(score, 2) + "%"
	if degraded {
		scoreText += " (Degraded)"
	}

	t.maroto.AddRow(10,
		text.NewCol(5, "Scan coverage", defaultProps),
		text.NewCol(2, fmt.Sprintf("%d evaluated", evaluated), defaultProps),
		text.NewCol(2, fmt.Sprintf("%d total", total), defaultProps),
		text.NewCol(3, scoreText, defaultProps),
	)

	if len(unexaminedKinds) > 0 {
		var parts []string
		for _, uk := range unexaminedKinds {
			if uk.Kind != "" && uk.GroupVersionResource != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", uk.Kind, uk.GroupVersionResource))
			} else if uk.Kind != "" {
				parts = append(parts, uk.Kind)
			} else if uk.GroupVersionResource != "" {
				parts = append(parts, uk.GroupVersionResource)
			}
		}
		if len(parts) > 0 {
			t.maroto.AddAutoRow(text.NewCol(12, "Unexamined resource kinds:", props.Text{
				Style:  fontstyle.Italic,
				Family: fontfamily.Arial,
				Align:  align.Left,
				Top:    1,
				Size:   7,
				Color:  &props.BlackColor,
			}))
			for _, part := range parts {
				t.maroto.AddAutoRow(text.NewCol(12, fmt.Sprintf("  • %s", part), props.Text{
					Style:  fontstyle.Italic,
					Family: fontfamily.Arial,
					Align:  align.Left,
					Top:    0.5,
					Size:   7,
					Color:  &props.BlackColor,
				}))
			}
		}
	}
}

// GenerateSkippedControlsTable is responsible for adding skipped control data in table format to the pdf (#3884)
func (t *Template) GenerateSkippedControlsTable(tableRows *[]SkippedControlTableObject) error {
	rows, err := list.Build[SkippedControlTableObject](*tableRows)
	if err != nil {
		return err
	}
	t.maroto.AddRows(rows...)
	t.maroto.AddRows(
		line.NewAutoRow(props.Line{Thickness: 0.3, SizePercent: 100}),
		row.New(2),
	)
	return nil
}

// GenerateInfoRows is responsible for adding the information in pdf
func (t *Template) GenerateInfoRows(rows []string) *Template {
	for _, row := range rows {
		t.maroto.AddAutoRow(text.NewCol(12, row, props.Text{
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

	t.maroto.AddRow(10,
		text.NewCol(5, "Resource summary", defaultProps),
		text.NewCol(2, fmt.Sprintf("%d", totalFailed), defaultProps),
		text.NewCol(2, fmt.Sprintf("%d", total), defaultProps),
		text.NewCol(2, cautils.ComplianceScoreToString(score, 2)+"%", defaultProps),
	)
}

func (t *Template) GetStructure() *node.Node[core.Structure] {
	return t.maroto.GetStructure()
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

// ImageTableObject maps a single CVE row for the image-scan PDF report (#2782)
type ImageTableObject struct {
	cveID        string
	packageName  string
	version      string
	severity     string
	fixVersions  string
	getTextColor getTextColorFunc
}

func NewImageTableRow(cveID, packageName, version, severity, fixVersions string, getTextColor getTextColorFunc) *ImageTableObject {
	return &ImageTableObject{
		cveID:        cveID,
		packageName:  packageName,
		version:      version,
		severity:     severity,
		fixVersions:  fixVersions,
		getTextColor: getTextColor,
	}
}

func (t ImageTableObject) GetHeader() core.Row {
	return row.New(10).Add(
		text.NewCol(1, "Severity", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(2, "CVE ID", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(4, "Package", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(2, "Version", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(3, "Fixed in", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
	)
}

func (t ImageTableObject) GetContent(i int) core.Row {
	r := row.New(3).Add(
		text.NewCol(1, t.severity, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: t.getTextColor(t.severity)}),
		text.NewCol(2, t.cveID, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: &props.Color{}}),
		text.NewCol(4, t.packageName, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(2, t.version, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(3, t.fixVersions, props.Text{VerticalPadding: 1, Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
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

// SkippedControlTableObject maps a single skipped or unevaluated control for the PDF report (#3884)
type SkippedControlTableObject struct {
	severity     string
	ref          string
	name         string
	reason       string
	getTextColor getTextColorFunc
}

// NewSkippedControlTableRow constructs a SkippedControlTableObject for rendering.
func NewSkippedControlTableRow(severity, ref, name, reason string, getTextColor getTextColorFunc) *SkippedControlTableObject {
	return &SkippedControlTableObject{
		severity:     severity,
		ref:          ref,
		name:         name,
		reason:       reason,
		getTextColor: getTextColor,
	}
}

func (s SkippedControlTableObject) GetHeader() core.Row {
	return row.New(10).Add(
		text.NewCol(1, "Severity", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(2, "Control reference", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(4, "Control name", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
		text.NewCol(5, "Skip reason", props.Text{Size: 6, Family: fontfamily.Arial, Style: fontstyle.Bold}),
	)
}

func (s SkippedControlTableObject) GetContent(i int) core.Row {
	severityColor := &props.BlackColor
	if s.getTextColor != nil {
		severityColor = s.getTextColor(s.severity)
	}
	r := row.New().Add(
		text.NewCol(1, s.severity, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: severityColor}),
		text.NewCol(2, s.ref, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6, Color: &props.Color{}}),
		text.NewCol(4, s.name, props.Text{Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
		text.NewCol(5, s.reason, props.Text{VerticalPadding: 1, Style: fontstyle.Normal, Family: fontfamily.Courier, Size: 6}),
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
