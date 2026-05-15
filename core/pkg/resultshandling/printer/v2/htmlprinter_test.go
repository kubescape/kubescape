package printer

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHtmlPrinter(t *testing.T) {
	hp := NewHtmlPrinter()
	assert.NotNil(t, hp)
	assert.Empty(t, hp)
}

func TestSetWriter_Html(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.html",
		},
		{
			name:       "Output file name already contains .html",
			outputFile: "customFilename.html",
			expected:   "customFilename.html",
		},
		{
			// Regression for issue-6: empty --output must NOT fall through to
			// stdout — default to ./report.html instead.
			name:       "Output file name is empty defaults to report.html",
			outputFile: "",
			expected:   "report.html",
		},
		{
			name:       "Whitespace-only output file is treated as empty",
			outputFile: "   ",
			expected:   "report.html",
		},
		{
			name:       "Surrounding whitespace is trimmed",
			outputFile: "  myfile  ",
			expected:   "myfile.html",
		},
	}

	hp := NewHtmlPrinter()
	ctx := context.Background()

	tmp := t.TempDir()
	origWd, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp.SetWriter(ctx, tt.outputFile)
			assert.Equal(t, tt.expected, hp.writer.Name())
			assert.NotEqual(t, "/dev/stdout", hp.writer.Name(),
				"HTML printer must never write to stdout")
		})
	}
}
