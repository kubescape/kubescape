package printer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPrometheusPrinter(t *testing.T) {
	// For verbose mode false
	verboseMode := false
	promPrinter := NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)

	// For verbose mode true
	verboseMode = true
	promPrinter = NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)
}

func TestSetWriter(t *testing.T) {
	// Test case 1: Empty outputFile
	outputFile := ""
	promPrinter := &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), outputFile)
	assert.Equal(t, os.Stdout, promPrinter.writer)

	// Test case 2: Valid outputFile
	outputFile = filepath.Join(os.TempDir(), "test.log")
	promPrinter = &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), outputFile)
	f, err := os.Open(outputFile)
	assert.NoError(t, err)
	defer f.Close()
	assert.NotNil(t, promPrinter.writer)
}

func TestScore(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score 100\n",
		},
	}

	promPrinter := NewPrometheusPrinter(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdout to a buffer
			rescueStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			promPrinter.Score(tt.score)

			w.Close()
			got, _ := io.ReadAll(r)
			os.Stdout = rescueStdout
			assert.Equal(t, tt.want, string(got))
		})
	}
}
