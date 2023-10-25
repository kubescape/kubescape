package configurationprinter

import (
	"testing"

	"github.com/olekukonko/tablewriter"
)

func TestWorkloadScan_InitCategoryTableData(t *testing.T) {

	expectedHeader := []string{"", "Control name", "Docs"}
	expectedAlign := []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER}

	workloadPrinter := NewWorkloadPrinter()

	headers, columnAligments := workloadPrinter.initCategoryTableData()

	for i := range headers {
		if headers[i] != expectedHeader[i] {
			t.Errorf("Expected header %s, got %s", expectedHeader[i], headers[i])
		}
	}

	for i := range columnAligments {
		if columnAligments[i] != expectedAlign[i] {
			t.Errorf("Expected column alignment %d, got %d", expectedAlign[i], columnAligments[i])
		}
	}

}
