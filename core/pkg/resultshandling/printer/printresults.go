package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

var INDENT = "   "

const (
	PrettyFormat       string = "pretty-printer"
	JsonFormat         string = "json"
	JunitResultFormat  string = "junit"
	PrometheusFormat   string = "prometheus"
	PdfFormat          string = "pdf"
	HtmlFormat         string = "html"
	SARIFFormat        string = "sarif"
	GitLabSASTFormat   string = "gitlab-sast"
	YamlFormat         string = "yaml"
	CsvFormat          string = "csv"
	MarkdownFormat     string = "markdown"
	CycloneDXFormat    string = "cyclonedx-json"
	SPDXFormat         string = "spdx-json"
	PolicyReportFormat string = "policyreport"
	OtelFormat         string = "otel"
)

// AllFormats lists every output format kubescape can emit.
var AllFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, YamlFormat, CsvFormat, MarkdownFormat, CycloneDXFormat, SPDXFormat, PolicyReportFormat, OtelFormat}

// ImageFormats lists formats whose printers support image-scan data. CSV is
// deliberately excluded: CsvPrinter.ActionPrint requires opaSessionObj and
// errors out on image scans (#2743) — a format must not be advertised as
// image-scan-capable unless its printer actually handles that path.
//
// CycloneDXFormat and SPDXFormat are the inverse: they encode the SBOM that
// only exists on image scans, so they are image-scan-only (see ValidatePrinter).
var ImageFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, YamlFormat, CycloneDXFormat, SPDXFormat, OtelFormat}

const (
	JsonOutputExt         = ".json"
	JunitOutputExt        = ".xml"
	SARIFOutputExt        = ".sarif"
	HtmlOutputExt         = ".html"
	PdfOutputExt          = ".pdf"
	PrometheusOutputExt   = ".txt"
	PrettyOutputExt       = ".txt"
	YamlOutputExt         = ".yaml"
	CsvOutputExt          = ".csv"
	MarkdownOutputExt     = ".md"
	CycloneDXOutputExt    = ".cdx.json"
	SPDXOutputExt         = ".spdx.json"
	PolicyReportOutputExt = ".yaml"
	// OtelOutputExt is nominal only: the "otel" format never writes a file
	// (see OtelPrinter.SetWriter), it exports over OTLP instead. It is
	// listed here purely so FormatOutputExt stays total over AllFormats.
	OtelOutputExt = ".otel"
)

// HasOutputExt reports whether outputFile already ends with ext, compared
// case-insensitively. Every v2 printer's SetWriter previously re-implemented
// this check with a case-sensitive filepath.Ext(...) != ext comparison, so
// --output Report.JSON (or any differently-cased extension) failed the check
// in every one of them and silently doubled up: Report.JSON.json.
func HasOutputExt(outputFile, ext string) bool {
	if len(outputFile) < len(ext) {
		return false
	}
	return strings.EqualFold(outputFile[len(outputFile)-len(ext):], ext)
}

// FormatOutputExt maps a format to the extension its printer enforces in
// SetWriter. Callers resolving an --output path must read it from here rather
// than re-deriving it, so a format can never resolve to a path its printer
// does not write. Every entry in AllFormats is covered.
var FormatOutputExt = map[string]string{
	PrettyFormat:       PrettyOutputExt,
	JsonFormat:         JsonOutputExt,
	JunitResultFormat:  JunitOutputExt,
	PrometheusFormat:   PrometheusOutputExt,
	PdfFormat:          PdfOutputExt,
	HtmlFormat:         HtmlOutputExt,
	SARIFFormat:        SARIFOutputExt,
	GitLabSASTFormat:   JsonOutputExt,
	YamlFormat:         YamlOutputExt,
	CsvFormat:          CsvOutputExt,
	MarkdownFormat:     MarkdownOutputExt,
	CycloneDXFormat:    CycloneDXOutputExt,
	SPDXFormat:         SPDXOutputExt,
	PolicyReportFormat: PolicyReportOutputExt,
	OtelFormat:         OtelOutputExt,
}

type IPrinter interface {
	PrintNextSteps()
	ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error
	SetWriter(ctx context.Context, outputFile string) error
	Score(score float32)
}

// outputDirPerm restricts created output directories to the owner (rwx------
// would be too tight for shared setups, so this keeps group read/traverse),
// instead of os.ModePerm (0777, world-writable) which scan output/report
// directories have no reason to be.
const outputDirPerm = 0o750

func GetWriter(ctx context.Context, outputFile string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := os.Create(filepath.Clean(outputFile))
		if err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}

// GetWriterNoFallback opens an explicitly requested output path. Unlike the
// legacy helpers, it never redirects an error to stdout or a temporary file:
// callers can return the setup failure before a scan starts.
func GetWriterNoFallback(outputFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err != nil {
		return nil, fmt.Errorf("create output directory for %q: %w", outputFile, err)
	}
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("open output file %q: %w", outputFile, err)
	}
	return f, nil
}

// GetWriterNoStdoutFallback opens outputFile for writing for formats whose
// output (binary, markup) would corrupt a TTY if dumped to stdout. On any
// failure to open the requested file it falls back to a uniquely-named file
// under os.TempDir() using tempPattern (e.g. "kubescape-report-*.pdf"). If
// that fails it tries os.DevNull, then a pipe-based sink as a last resort.
// It never returns os.Stdout.
func GetWriterNoStdoutFallback(ctx context.Context, outputFile, tempPattern string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err == nil {
			if f, err := os.Create(filepath.Clean(outputFile)); err == nil {
				return f
			} else {
				logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			}
		} else {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
		}
	}
	if tmp, err := os.CreateTemp("", tempPattern); err == nil {
		logger.L().Ctx(ctx).Warning("could not write to requested output path; falling back to temp file",
			helpers.String("filename", tmp.Name()))
		return tmp
	} else {
		logger.L().Ctx(ctx).Error(fmt.Sprintf("failed to create temp output file, reason: %s", err.Error()))
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// os.DevNull should always be openable; if not, fall back to a temp file
		// so we still return a writable, closable handle.
		if tmp, tmpErr := os.CreateTemp(".", tempPattern); tmpErr == nil {
			logger.L().Ctx(ctx).Warning("failed to open os.DevNull; falling back to temp file",
				helpers.String("filename", tmp.Name()))
			return tmp
		}
		r, w, pipeErr := os.Pipe()
		if pipeErr == nil {
			go func() {
				_, _ = io.Copy(io.Discard, r)
				_ = r.Close()
			}()
			return w
		}
		// Final fallback: return a non-nil file handle even if it is not writable.
		return os.NewFile(^uintptr(0), os.DevNull)
	}
	return devNull
}

func LogOutputFile(fileName string) {
	if fileName != os.Stdout.Name() && fileName != os.Stderr.Name() && fileName != os.DevNull {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}
}
