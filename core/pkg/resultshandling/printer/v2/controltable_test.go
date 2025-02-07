package printer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/kubescape/kubescape/v3/internal/testutils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
)

func Test_generateRowPdf(t *testing.T) {

	mockSummary, err := mockSummaryDetails()
	if err != nil {
		t.Errorf("Error in creating mock summary %s", err)
	}

	infoToPrintInfoMap := mapInfoToPrintInfo(mockSummary.Controls)
	sortedControlIDs := getSortedControlsIDs(mockSummary.Controls)

	var rows []TableRow

	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := *generateTableRow(mockSummary.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap)
			rows = append(rows, row)
		}
	}

	for _, row := range rows {
		//validating severity column
		if row.severity != "Low" && row.severity != "Medium" && row.severity != "High" && row.severity != "Critical" {
			t.Errorf("got %s, want either of these: %s", row.severity, "Low, Medium, High, Critical")
		}

		// Validating length of control ID
		if len(row.ref) > 6 {
			t.Errorf("got %s, want %s", row.ref, "less than 7 characters")
		}

		// Validating length of control name
		if len(row.name) > controlNameMaxLength {
			t.Errorf("got %s, want %s", row.name, fmt.Sprintf("less than %d characters", controlNameMaxLength))
		}

		// Validating numeric fields
		_, err := strconv.Atoi(row.counterFailed)
		if err != nil {
			t.Errorf("got %s, want an integer %s", row.counterFailed, err)
		}

		_, err = strconv.Atoi(row.counterAll)
		if err != nil {
			t.Errorf("got %s, want an integer %s", row.counterAll, err)
		}

		assert.NotEmpty(t, row.complianceScore, "expected a non-empty string")

	}

}

func mockSummaryDetails() (*reportsummary.SummaryDetails, error) {
	data, err := os.ReadFile(filepath.Join(testutils.CurrentDir(), "testdata", "mock_summaryDetails.json"))
	if err != nil {
		return nil, err
	}

	var v *reportsummary.SummaryDetails

	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	return v, nil
}
