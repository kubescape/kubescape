package printer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJsonPrinter_ReturnsEmptyInstance(t *testing.T) {
	jp := NewJsonPrinter()
	assert.NotNil(t, jp)
	assert.Nil(t, jp.writer)
}

func TestJsonPrinterScore(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{name: "rounds fractional score", score: 20.7, want: "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n"},
		{name: "zero score", score: 0, want: "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n"},
		{name: "perfect score", score: 100, want: "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "jsonprinter-score")
			require.NoError(t, err)
			defer f.Close()

			oldStderr := os.Stderr
			os.Stderr = f
			defer func() { os.Stderr = oldStderr }()

			NewJsonPrinter().Score(tt.score)

			_, err = f.Seek(0, 0)
			require.NoError(t, err)
			got, err := io.ReadAll(f)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestJsonPrinterActionPrint(t *testing.T) {
	tests := []struct {
		name          string
		opaSessionObj *cautils.OPASessionObj
		checkJSON     func(t *testing.T, raw []byte)
	}{
		{
			name: "no frameworks falls back to a single unnamed report",
			opaSessionObj: &cautils.OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Score: 77,
					},
				},
			},
			checkJSON: func(t *testing.T, raw []byte) {
				var got reporthandling.FrameworkReport
				require.NoError(t, json.Unmarshal(raw, &got))
				assert.Empty(t, got.Name)
				assert.Equal(t, float32(77), got.Score)
			},
		},
		{
			name: "single framework report marshals as a single object",
			opaSessionObj: &cautils.OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Score:      77,
						Frameworks: []reportsummary.FrameworkSummary{{Name: "NSA", Score: 90}},
					},
				},
			},
			checkJSON: func(t *testing.T, raw []byte) {
				var got reporthandling.FrameworkReport
				require.NoError(t, json.Unmarshal(raw, &got))
				assert.Equal(t, "NSA", got.Name)
				assert.Equal(t, float32(90), got.Score) // framework score, not SummaryDetails.Score
			},
		},
		{
			name: "multiple framework reports marshal as an array",
			opaSessionObj: &cautils.OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Frameworks: []reportsummary.FrameworkSummary{
							{Name: "NSA", Score: 90},
							{Name: "MITRE", Score: 55},
						},
					},
				},
			},
			checkJSON: func(t *testing.T, raw []byte) {
				var got []reporthandling.FrameworkReport
				require.NoError(t, json.Unmarshal(raw, &got))
				require.Len(t, got, 2)
				assert.Equal(t, "NSA", got[0].Name)
				assert.Equal(t, float32(90), got[0].Score)
				assert.Equal(t, "MITRE", got[1].Name)
				assert.Equal(t, float32(55), got[1].Score)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFile := filepath.Join(t.TempDir(), "report.json")
			writer, err := os.Create(outputFile)
			require.NoError(t, err)

			jp := NewJsonPrinter()
			jp.writer = writer

			jp.ActionPrint(context.Background(), tt.opaSessionObj, nil)
			require.NoError(t, writer.Close())

			got, err := os.ReadFile(outputFile)
			require.NoError(t, err)
			tt.checkJSON(t, got)
		})
	}
}

func TestJsonPrinterCloseWriter(t *testing.T) {
	t.Run("closes a file writer", func(t *testing.T) {
		writer, err := os.Create(filepath.Join(t.TempDir(), "report.json"))
		require.NoError(t, err)

		jp := NewJsonPrinter()
		jp.writer = writer
		jp.CloseWriter()

		assert.Error(t, writer.Close(), "expected writer to already be closed")
	})

	t.Run("does not close stdout", func(t *testing.T) {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		defer r.Close()
		defer w.Close()

		old := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = old }()

		jp := NewJsonPrinter()
		jp.writer = os.Stdout
		jp.CloseWriter()

		_, err = os.Stdout.Write([]byte("still open"))
		assert.NoError(t, err, "os.Stdout should remain usable")
	})
}
