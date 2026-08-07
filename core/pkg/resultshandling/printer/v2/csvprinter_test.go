package printer

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func csvSessionFixture() *cautils.OPASessionObj {
	controlID1 := "C-0057"
	controlID2 := "C-0058"
	resourceID1 := "apps/v1/Deployment/default/demo"
	resourceID2 := "apps/v1/Deployment/default/absent"

	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)

	ac1 := resourcesresults.ResourceAssociatedControl{
		ControlID: controlID1,
		Name:      "Privileged container",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}

	ac2 := resourcesresults.ResourceAssociatedControl{
		ControlID: controlID2,
		Name:      "Run as root",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}

	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult[resourceID1] = resourcesresults.Result{
		ResourceID:         resourceID1,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac1, ac2},
	}
	session.ResourcesResult[resourceID2] = resourcesresults.Result{
		ResourceID:         resourceID2,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac1},
	}
	session.AllResources[resourceID1] = lw

	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID1: reportsummary.ControlSummary{
					ControlID:   controlID1,
					Name:        "Privileged container",
					ScoreFactor: 9.0, // Critical severity
				},
				controlID2: reportsummary.ControlSummary{
					ControlID:   controlID2,
					Name:        "Run as root",
					ScoreFactor: 5.0, // Medium severity
				},
			},
		},
	}

	return session
}

func TestNewCsvPrinter(t *testing.T) {
	cp := NewCsvPrinter()
	assert.NotNil(t, cp)
}

func TestSetWriter_Csv(t *testing.T) {
	cp := NewCsvPrinter()
	assert.NotNil(t, cp)

	// Test without outputFile (should use stdout)
	cp.SetWriter(context.TODO(), "")
	assert.NotNil(t, cp.writer)
	cp.CloseWriter()
}

func TestScore_Csv(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	cp := NewCsvPrinter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "csvPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer func() {
				_ = f.Close()
			}()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			cp.Score(tt.score)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestActionPrint_Csv(t *testing.T) {
	session := csvSessionFixture()

	tmpCsv, err := os.CreateTemp("", "csv-regression-*.csv")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpCsv.Name())
	}()

	cp := NewCsvPrinter()
	cp.writer = tmpCsv
	cp.ActionPrint(context.TODO(), session, nil)
	cp.CloseWriter()

	f, err := os.Open(tmpCsv.Name())
	assert.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	assert.NoError(t, err)

	// We expect 1 header row + 3 data rows (2 for resourceID1, 1 for resourceID2)
	assert.Equal(t, 4, len(records))

	expectedHeader := []string{
		"Control Name",
		"Control ID",
		"Severity",
		"Status",
		"Resource Name",
		"Resource Kind",
		"Resource Namespace",
		"API Version",
	}
	assert.Equal(t, expectedHeader, records[0], "Header should match expected")

	// The order of results isn't strictly guaranteed by a map iteration, but we can verify the rows exist.
	var failedDemo, passedDemo, failedAbsent bool
	for _, row := range records[1:] {
		if row[0] == "Privileged container" && row[1] == "C-0057" && row[2] == "Critical" && row[3] == "failed" {
			if row[4] == "demo" && row[5] == "Deployment" && row[6] == "default" && row[7] == "apps/v1" {
				failedDemo = true
			} else if row[4] == "" && row[5] == "" && row[6] == "" && row[7] == "" {
				failedAbsent = true
			}
		} else if row[0] == "Run as root" && row[1] == "C-0058" && row[2] == "Medium" && row[3] == "passed" {
			if row[4] == "demo" && row[5] == "Deployment" && row[6] == "default" && row[7] == "apps/v1" {
				passedDemo = true
			}
		}
	}

	assert.True(t, failedDemo, "expected failed control row for demo resource")
	assert.True(t, passedDemo, "expected passed control row for demo resource")
	assert.True(t, failedAbsent, "expected failed control row for absent resource (with empty columns)")
}
