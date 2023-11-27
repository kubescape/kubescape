package printer

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPdfPrinter(t *testing.T) {
	pp := NewPdfPrinter()
	assert.NotNil(t, pp)
	assert.Empty(t, pp)
}

func TestScore_Pdf(t *testing.T) {
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
			name:  "Score less than 0",
			score: -20.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	pp := NewPdfPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			// Print the score using the `Score` function
			pp.Score(tt.score)

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := ioutil.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSetWriter_Pdf(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name contains doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.pdf",
		},
		{
			name:       "Output file name contains .pdf",
			outputFile: "customFilename.pdf",
			expected:   "customFilename.pdf",
		},
		{
			name:       "Output file name is empty",
			outputFile: "",
			expected:   "/dev/stdout",
		},
	}

	pp := NewPdfPrinter()
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			pp.SetWriter(ctx, tt.outputFile)
			assert.Equal(t, tt.expected, pp.writer.Name())
		})
	}
}
