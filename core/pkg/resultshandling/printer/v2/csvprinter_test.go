package printer

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

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
	session := cautils.NewOPASessionObjMock()

	tmpCsv, err := os.CreateTemp("", "csv-regression-*.csv")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpCsv.Name())
	}()

	cp := NewCsvPrinter()
	cp.writer = tmpCsv
	cp.ActionPrint(context.Background(), session, nil)
	assert.NoError(t, tmpCsv.Close())

	// Read CSV and verify header
	f, err := os.Open(tmpCsv.Name())
	assert.NoError(t, err)
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, len(records), 1, "Should have at least the header")

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
}
