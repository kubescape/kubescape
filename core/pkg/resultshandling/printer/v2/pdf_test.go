package printer

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/kubescape/kubescape/v3/core/cautils"
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
			name:  "Fractional score below perfect",
			score: 99.5,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 99\n",
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
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			pp.Score(tt.score)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
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
			name:       "Output file name is empty defaults to report.pdf",
			outputFile: "",
			expected:   "report.pdf",
		},
		{
			name:       "Whitespace-only output file is treated as empty",
			outputFile: "   ",
			expected:   "report.pdf",
		},
		{
			name:       "Surrounding whitespace is trimmed",
			outputFile: "  myfile  ",
			expected:   "myfile.pdf",
		},
	}

	pp := NewPdfPrinter()
	ctx := context.Background()

	tmp := t.TempDir()
	origWd, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp.SetWriter(ctx, tt.outputFile)
			// Each call opens a new file and overwrites the previous writer,
			// so every iteration leaks a handle. Windows will not remove the
			// temp dir these land in while any of them is still open.
			w := pp.writer
			defer w.Close()
			assert.Equal(t, tt.expected, pp.writer.Name())
			assert.NotEqual(t, "/dev/stdout", pp.writer.Name(),
				"PDF printer must never write to stdout")
		})
	}
}

func TestGetImageTableObjects_EmptyCVEs(t *testing.T) {
	pp := NewPdfPrinter()
	rows, fixableCVEs := pp.getImageTableObjects(nil)

	if rows == nil {
		t.Fatal("expected non-nil rows for empty CVE list, got nil")
	}
	if len(*rows) != 1 {
		t.Fatalf("expected 1 placeholder row for empty CVE list, got %d", len(*rows))
	}
	if fixableCVEs != 0 {
		t.Fatalf("expected 0 fixable CVEs, got %d", fixableCVEs)
	}
}

func TestGenerateImagePdf_NoVulnerabilities(t *testing.T) {
	pp := NewPdfPrinter()
	data := []cautils.ImageScanData{
		{Image: "clean-image:latest", Matches: match.NewMatches()},
	}
	out, err := pp.generateImagePdf(data)
	if err != nil {
		t.Fatalf("expected no error generating PDF for clean image, got: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty PDF bytes for clean image")
	}
}
