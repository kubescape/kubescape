package printer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	baseprinter "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type writerCase struct {
	name        string
	format      string
	baseName    string
	newPrinter  func() setWriterPrinter
	writerName  func(setWriterPrinter) string
	closeWriter func(setWriterPrinter) error
}

type setWriterPrinter interface {
	SetWriter(context.Context, string) error
}

func TestSetWriterUsesSharedOutputResolution(t *testing.T) {
	cases := []writerCase{
		{
			name:       "json",
			format:     baseprinter.JsonFormat,
			baseName:   jsonOutputFile,
			newPrinter: func() setWriterPrinter { return NewJsonPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*JsonPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*JsonPrinter).CloseWriter()
			},
		},
		{
			name:       "yaml",
			format:     baseprinter.YamlFormat,
			baseName:   yamlOutputFile,
			newPrinter: func() setWriterPrinter { return NewYamlPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*YamlPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*YamlPrinter).CloseWriter()
			},
		},
		{
			name:       "csv",
			format:     baseprinter.CsvFormat,
			baseName:   csvOutputFile,
			newPrinter: func() setWriterPrinter { return NewCsvPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*CsvPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*CsvPrinter).CloseWriter()
			},
		},
		{
			name:       "junit",
			format:     baseprinter.JunitResultFormat,
			baseName:   junitOutputFile,
			newPrinter: func() setWriterPrinter { return NewJunitPrinter(false) },
			writerName: func(p setWriterPrinter) string { return p.(*JunitPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*JunitPrinter).CloseWriter()
			},
		},
		{
			name:       "prometheus",
			format:     baseprinter.PrometheusFormat,
			baseName:   prometheusOutputFile,
			newPrinter: func() setWriterPrinter { return NewPrometheusPrinter(false) },
			writerName: func(p setWriterPrinter) string { return p.(*PrometheusPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*PrometheusPrinter).CloseWriter()
			},
		},
		{
			name:       "sarif",
			format:     baseprinter.SARIFFormat,
			baseName:   sarifOutputFile,
			newPrinter: func() setWriterPrinter { return NewSARIFPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*SARIFPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*SARIFPrinter).CloseWriter()
			},
		},
		{
			name:       "gitlab-sast",
			format:     baseprinter.GitLabSASTFormat,
			baseName:   gitLabSASTOutputFile,
			newPrinter: func() setWriterPrinter { return NewGitLabSASTPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*GitLabSASTPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*GitLabSASTPrinter).CloseWriter()
			},
		},
		{
			name:       "cyclonedx",
			format:     baseprinter.CycloneDXFormat,
			baseName:   cyclonedxOutputFile,
			newPrinter: func() setWriterPrinter { return NewCycloneDXPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*CycloneDXPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*CycloneDXPrinter).CloseWriter()
			},
		},
		{
			name:       "spdx",
			format:     baseprinter.SPDXFormat,
			baseName:   spdxOutputFile,
			newPrinter: func() setWriterPrinter { return NewSPDXPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*SPDXPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*SPDXPrinter).CloseWriter()
			},
		},
		{
			name:       "pretty",
			format:     baseprinter.PrettyFormat,
			baseName:   prettyOutputFile,
			newPrinter: func() setWriterPrinter { return &PrettyPrinter{} },
			writerName: func(p setWriterPrinter) string { return p.(*PrettyPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*PrettyPrinter).CloseWriter()
			},
		},
		{
			name:       "html",
			format:     baseprinter.HtmlFormat,
			baseName:   htmlOutputFile,
			newPrinter: func() setWriterPrinter { return NewHtmlPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*HtmlPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*HtmlPrinter).CloseWriter()
			},
		},
		{
			name:       "pdf",
			format:     baseprinter.PdfFormat,
			baseName:   pdfOutputFile,
			newPrinter: func() setWriterPrinter { return NewPdfPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*PdfPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*PdfPrinter).CloseWriter()
			},
		},
		{
			name:       "markdown",
			format:     baseprinter.MarkdownFormat,
			baseName:   markdownOutputFile,
			newPrinter: func() setWriterPrinter { return NewMarkdownPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*MarkdownPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*MarkdownPrinter).CloseWriter()
			},
		},
		{
			name:       "policyreport",
			format:     baseprinter.PolicyReportFormat,
			baseName:   policyReportOutputFile,
			newPrinter: func() setWriterPrinter { return NewPolicyReportPrinter() },
			writerName: func(p setWriterPrinter) string { return p.(*PolicyReportPrinter).writer.Name() },
			closeWriter: func(p setWriterPrinter) error {
				return p.(*PolicyReportPrinter).CloseWriter()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/trims explicit output", func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "scan")
			want, explicit := baseprinter.ResolveOutputFile(tc.format, "  "+base+"  ", tc.baseName)
			require.True(t, explicit)

			p := tc.newPrinter()
			require.NoError(t, p.SetWriter(context.Background(), "  "+base+"  "))
			t.Cleanup(func() { assert.NoError(t, tc.closeWriter(p)) })

			assert.Equal(t, want, tc.writerName(p))
			assert.NotContains(t, filepath.Base(tc.writerName(p)), " ")
		})

		t.Run(tc.name+"/whitespace explicit output uses default report name", func(t *testing.T) {
			workingDir := t.TempDir()
			originalDir, err := os.Getwd()
			require.NoError(t, err)
			require.NoError(t, os.Chdir(workingDir))
			t.Cleanup(func() { require.NoError(t, os.Chdir(originalDir)) })

			want, explicit := baseprinter.ResolveOutputFile(tc.format, "   ", tc.baseName)
			require.True(t, explicit)

			p := tc.newPrinter()
			require.NoError(t, p.SetWriter(context.Background(), "   "))
			t.Cleanup(func() { assert.NoError(t, tc.closeWriter(p)) })

			assert.Equal(t, want, filepath.Base(tc.writerName(p)))
			assert.FileExists(t, filepath.Join(workingDir, want))
		})

		t.Run(tc.name+"/keeps existing extension case", func(t *testing.T) {
			dir := t.TempDir()
			ext := baseprinter.FormatOutputExt[tc.format]
			if tc.format == baseprinter.YamlFormat {
				ext = ".yml"
			}
			target := filepath.Join(dir, "Report"+strings.ToUpper(ext))
			want, explicit := baseprinter.ResolveOutputFile(tc.format, target, tc.baseName)
			require.True(t, explicit)

			p := tc.newPrinter()
			require.NoError(t, p.SetWriter(context.Background(), target))
			t.Cleanup(func() { assert.NoError(t, tc.closeWriter(p)) })

			assert.Equal(t, want, tc.writerName(p))
		})
	}
}
