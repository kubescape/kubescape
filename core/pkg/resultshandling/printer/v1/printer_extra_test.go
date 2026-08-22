package printer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonPrinterSetWriter(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		wantSuffix string
	}{
		{
			name:       "adds json extension",
			outputFile: filepath.Join(t.TempDir(), "scan-result"),
			wantSuffix: "scan-result.json",
		},
		{
			name:       "keeps json extension",
			outputFile: filepath.Join(t.TempDir(), "scan-result.json"),
			wantSuffix: "scan-result.json",
		},
		{
			name:       "blank output uses default report name",
			outputFile: "   ",
			wantSuffix: "report.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workingDir := t.TempDir()
			originalDir, err := os.Getwd()
			assert.NoError(t, err)
			assert.NoError(t, os.Chdir(workingDir))
			t.Cleanup(func() { assert.NoError(t, os.Chdir(originalDir)) })

			p := NewJsonPrinter()
			p.SetWriter(context.Background(), tt.outputFile)
			defer p.writer.Close()

			assert.True(t, strings.HasSuffix(p.writer.Name(), tt.wantSuffix), p.writer.Name())
		})
	}
}

func TestJsonPrinterSetWriterUsesStdoutForEmptyOutput(t *testing.T) {
	p := NewJsonPrinter()

	p.SetWriter(context.Background(), "")

	assert.Equal(t, os.Stdout.Name(), p.writer.Name())
}
