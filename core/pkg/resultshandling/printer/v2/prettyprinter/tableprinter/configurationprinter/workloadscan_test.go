package configurationprinter

import (
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/assert"
)

func TestWorkloadScan_InitCategoryTableData(t *testing.T) {

	expectedHeader := []string{"", "Control name", "Docs"}
	expectedAlign := []table.ColumnConfig{{Number: 1, Align: text.AlignCenter}, {Number: 2, Align: text.AlignLeft}, {Number: 3, Align: text.AlignCenter}}

	workloadPrinter := NewWorkloadPrinter()

	headers, columnAlignments := workloadPrinter.initCategoryTableData()

	for i := range headers {
		if headers[i] != expectedHeader[i] {
			t.Errorf("Expected header %s, got %s", expectedHeader[i], headers[i])
		}
	}

	for i := range columnAlignments {
		assert.Equal(t, expectedAlign[i], columnAlignments[i])
	}

}
