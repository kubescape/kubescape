package pdf_test

import (
	"testing"

	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/johnfercher/maroto/v2/pkg/test"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/pdf"
	"github.com/stretchr/testify/assert"
)

func TestGetPdf(t *testing.T) {
	t.Run("when GetPdf is called, it should return pdf bytes", func(t *testing.T) {

		template := pdf.NewReportTemplate().GenerateHeader("Framework test 1, Framework test 2", "2024-04-01 20:31:00")
		bytes, err := template.GetPdf()

		assert.Nil(t, err)
		assert.NotNil(t, bytes)
	})
}

func TestGenerateHeader(t *testing.T) {
	t.Run("when generateHeader is called, it should set the header in the pdf", func(t *testing.T) {
		template := pdf.NewReportTemplate().GenerateHeader("Framework test 1, Framework test 2", "2024-04-01 20:31:00")

		node := template.GetStructure()

		assert.NotNil(t, node)
		test.New(t).Assert(node).Equals("headerTemplate.json")
	})
}

func TestGenerateTable(t *testing.T) {
	t.Run("when generateTable is called, it should set the table in the pdf", func(t *testing.T) {
		TableObjectMock := pdf.NewTableRow(
			"ref", "name", "failed", "all", "severity", "score",
			func(severity string) *props.Color { return &props.Color{Red: 0, Blue: 0, Green: 0} },
		)

		template := pdf.NewReportTemplate()

		err := template.GenerateTable(&[]pdf.TableObject{*TableObjectMock}, 100, 10, 10.0)

		assert.Nil(t, err)
		test.New(t).Assert(template.GetStructure()).Equals("tableTemplate.json")
	})
}

func TestGenerateInfoRows(t *testing.T) {
	t.Run("when generateInfoRows is called, it should set the info rows in the pdf", func(t *testing.T) {

		template := pdf.NewReportTemplate().GenerateInfoRows([]string{"row info 1", "row info 2", "row info 3"})

		assert.NotNil(t, template)
		test.New(t).Assert(template.GetStructure()).Equals("infoTemplate.json")
	})
}
