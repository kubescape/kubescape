package printer

import (
	"encoding/json"
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

	var results [][]string

	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			result := generateRowPdf(mockSummary.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfoMap, true)
			if len(result) > 0 {
				results = append(results, result)
			}
		}
	}

	for _, c := range results {
		//validating severity column
		if c[0] != "Low" && c[0] != "Medium" && c[0] != "High" && c[0] != "Critical" {
			t.Errorf("got %s, want either of these: %s", c[0], "Low, Medium, High, Critical")
		}

		// Validating length of control name
		if len(c[1]) > 53 {
			t.Errorf("got %s, want %s", c[1], "less than 54 characters")
		}

		// Validating numeric fields
		_, err := strconv.Atoi(c[2])
		if err != nil {
			t.Errorf("got %s, want an integer %s", c[2], err)
		}

		_, err = strconv.Atoi(c[3])
		if err != nil {
			t.Errorf("got %s, want an integer %s", c[3], err)
		}

		assert.NotEmpty(t, c[4], "expected a non-empty string")

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
