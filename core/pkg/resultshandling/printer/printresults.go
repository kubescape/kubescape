package printer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

var INDENT = "   "

const (
	PrettyFormat                  string = "pretty-printer"
	JsonFormat                    string = "json"
	JunitResultFormat             string = "junit"
	PrometheusFormat              string = "prometheus"
	PdfFormat                     string = "pdf"
	HtmlFormat                    string = "html"
	SARIFFormat                   string = "sarif"
	GitLabSASTFormat              string = "gitlab-sast"
	GitLabCodeQualityFormat       string = "gitlab-codequality"
	GitLabContainerScanningFormat string = "gitlab-container-scanning"
	GitHubActionsFormat           string = "github-actions"
	YamlFormat                    string = "yaml"
	CsvFormat                     string = "csv"
	MarkdownFormat                string = "markdown"
	CycloneDXFormat               string = "cyclonedx-json"
	SPDXFormat                    string = "spdx-json"
	PolicyReportFormat            string = "policyreport"
	ExceptionsFormat              string = "exceptions"
)

// AllFormats lists every output format kubescape can emit.
var AllFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, GitLabCodeQualityFormat, GitLabContainerScanningFormat, GitHubActionsFormat, YamlFormat, CsvFormat, MarkdownFormat, CycloneDXFormat, SPDXFormat, PolicyReportFormat, ExceptionsFormat}

// ImageFormats lists formats whose printers support image-scan data. A format
// must not be advertised as image-scan-capable unless its printer actually
// handles that path.
//
// CycloneDXFormat and SPDXFormat are the inverse: they encode the SBOM that
// only exists on image scans, so they are image-scan-only (see ValidatePrinter).
var ImageFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, GitLabContainerScanningFormat, GitHubActionsFormat, YamlFormat, CsvFormat, MarkdownFormat, CycloneDXFormat, SPDXFormat, PolicyReportFormat}

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
	ExceptionsOutputExt   = ".exceptions.json"
	GitHubActionsOutExt   = ".txt"
)

// CsvImageCompanionPath returns the file that receives the image
// vulnerabilities of a posture scan run with --scan-images and --format csv.
func CsvImageCompanionPath(postureReport string) string {
	return strings.TrimSuffix(postureReport, filepath.Ext(postureReport)) + "-vulnerabilities" + CsvOutputExt
}

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

// ResolveOutputFile applies Kubescape's shared output-path rules for a format:
// blank or whitespace-only explicit paths use defaultBaseName, missing
// extensions are appended from FormatOutputExt, and YAML accepts either .yaml
// or .yml. The returned bool tells callers whether the user explicitly asked
// for an output path before trimming, so whitespace-only paths still take the
// explicit-output error path instead of silently falling back to stdout.
func ResolveOutputFile(format, outputFile, defaultBaseName string) (string, bool) {
	explicitOutput := outputFile != ""
	if !explicitOutput {
		return outputFile, false
	}

	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		outputFile = defaultBaseName
	}

	// Well-known sinks bypass extension logic, exactly like PrettyPrinter
	// treats them: /dev/stdout resolves to real stdout (callers take the
	// non-explicit path into GetWriter with an empty name), and /dev/null
	// stays explicit so a failure to open it still surfaces as an error
	// instead of silently falling back to stdout.
	if outputFile == os.Stdout.Name() {
		return "", false
	}
	if outputFile == os.DevNull {
		return outputFile, true
	}

	// A trailing separator names a directory: write the default report name
	// inside it rather than a hidden file such as "reports/.json". A path
	// whose last element is "." or ".." (--output . or --output reports/..)
	// names a directory too, so it gets the same treatment instead of the
	// hidden file "..json". Append instead of filepath.Join, which would
	// clean "link/../" lexically and pick a different directory than the
	// filesystem does through a symlink.
	if defaultBaseName != "" {
		if os.IsPathSeparator(outputFile[len(outputFile)-1]) {
			outputFile += defaultBaseName
		} else if base := filepath.Base(outputFile); base == "." || base == ".." {
			outputFile += string(filepath.Separator) + defaultBaseName
		}
	}

	ext, ok := FormatOutputExt[format]
	if !ok || ext == "" {
		return outputFile, true
	}
	if ext == YamlOutputExt && HasOutputExt(outputFile, ".yml") {
		return outputFile, true
	}
	if HasOutputExt(outputFile, ext) {
		return outputFile, true
	}
	return outputFile + ext, true
}

func ResolveDefaultOutputFile(format, defaultBaseName string) string {
	outputFile, _ := ResolveOutputFile(format, " ", defaultBaseName)
	return outputFile
}

// DefaultBaseNameForFormat returns the fallback base file name used when
// --output is blank or names a directory.
func DefaultBaseNameForFormat(format string) string {
	switch format {
	case CycloneDXFormat, SPDXFormat:
		return "sbom"
	case ExceptionsFormat:
		return "exceptions"
	case GitHubActionsFormat:
		return "github-actions"
	case GitLabCodeQualityFormat:
		return "gl-code-quality-report"
	case GitLabContainerScanningFormat:
		return "gl-container-scanning-report"
	default:
		return "report"
	}
}

// FormatOutputExt maps a format to the extension its printer enforces in
// SetWriter. Callers resolving an --output path must read it from here rather
// than re-deriving it, so a format can never resolve to a path its printer
// does not write. Every entry in AllFormats is covered.
var FormatOutputExt = map[string]string{
	PrettyFormat:                  PrettyOutputExt,
	JsonFormat:                    JsonOutputExt,
	JunitResultFormat:             JunitOutputExt,
	PrometheusFormat:              PrometheusOutputExt,
	PdfFormat:                     PdfOutputExt,
	HtmlFormat:                    HtmlOutputExt,
	SARIFFormat:                   SARIFOutputExt,
	GitLabSASTFormat:              JsonOutputExt,
	GitLabCodeQualityFormat:       JsonOutputExt,
	GitLabContainerScanningFormat: JsonOutputExt,
	YamlFormat:                    YamlOutputExt,
	CsvFormat:                     CsvOutputExt,
	MarkdownFormat:                MarkdownOutputExt,
	CycloneDXFormat:               CycloneDXOutputExt,
	SPDXFormat:                    SPDXOutputExt,
	PolicyReportFormat:            PolicyReportOutputExt,
	ExceptionsFormat:              ExceptionsOutputExt,
	GitHubActionsFormat:           GitHubActionsOutExt,
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

// chmodFile is a test hook for permission-tightening failures.
var chmodFile = (*os.File).Chmod

// openFileForWrite opens path for writing with owner-only permissions, since
// scan reports can contain secrets. A pre-existing regular file is tightened
// to 0600 and only then truncated; if tightening is not possible, the file is
// left as it was and no report is written into it.
func openFileForWrite(path string) (*os.File, error) {
	return openOutputFile(path, false)
}

// openFileForPrinter is openFileForWrite for the result printers. It opens the
// file the same way but leaves an existing file's content alone until the
// printer calls PrepareOutput, right before it writes. A scan that fails
// before it has a report then leaves the old file as it was, and a file this
// call created is removed again by CloseOutput if nothing was ever written.
func openFileForPrinter(path string) (*os.File, error) {
	return openOutputFile(path, true)
}

// pendingOutput describes an output file opened by openFileForPrinter that no
// printer has written to yet.
type pendingOutput struct {
	// created is true when the open call created the file, so CloseOutput may
	// remove it again if the scan never got to write a report into it.
	created bool
}

// pendingOutputs maps an *os.File to its pendingOutput until PrepareOutput or
// CloseOutput settles it.
var pendingOutputs sync.Map

func openOutputFile(path string, deferTruncate bool) (*os.File, error) {
	// Reject a dangling symlink up front. O_EXCL returns ErrExist for the
	// symlink node even when its target does not exist, so the fallback open
	// below would create the missing target while leaving created=false.
	// CloseOutput would then skip the removal, leaving an empty target file.
	if linfo, lerr := os.Lstat(path); lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		if _, serr := os.Stat(path); serr != nil {
			return nil, fmt.Errorf("output path is a dangling symlink: %s", path)
		}
	}
	created := false
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		created = true
	case errors.Is(err, fs.ErrExist):
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat output file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return f, nil
	}
	if err := chmodFile(f, 0o600); err != nil {
		_ = f.Close()
		if created {
			_ = os.Remove(path)
		}
		return nil, fmt.Errorf("restrict output file permissions: %w", err)
	}
	if deferTruncate {
		pendingOutputs.Store(f, pendingOutput{created: created})
		return f, nil
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("truncate output file: %w", err)
	}
	return f, nil
}

// PrepareOutput clears the previous content of an output file that
// openFileForPrinter left untouched. Each printer calls it at the top of
// ActionPrint, once the scan has a report to write. It returns an error
// if the output writer is nil. It does nothing for stdout, a device, or
// a file that is already prepared.
func PrepareOutput(f *os.File) error {
	if f == nil {
		return fmt.Errorf("failed to write output: output writer is nil")
	}
	if _, pending := pendingOutputs.LoadAndDelete(f); !pending {
		return nil
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncate output file: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind output file: %w", err)
	}
	return nil
}

// CloseOutput closes an output file. If the file was created for this scan and
// never written to, because the scan failed first, it is removed so no empty
// report is left behind. A file that existed before the scan is never removed.
func CloseOutput(f *os.File) error {
	if f == nil {
		return nil
	}
	value, pending := pendingOutputs.LoadAndDelete(f)
	if !pending || !value.(pendingOutput).created {
		return f.Close()
	}
	path := f.Name()
	opened, statErr := f.Stat()
	closeErr := f.Close()
	if statErr == nil {
		// Only remove the path if it still names the file we created and is
		// still empty. A non-zero size means something wrote to it after we
		// opened it, so keep the file rather than destroy content.
		if onDisk, err := os.Stat(path); err == nil && os.SameFile(opened, onDisk) && opened.Size() == 0 {
			_ = os.Remove(path)
		}
	}
	return closeErr
}

// GetWriter opens outputFile for writing with owner-only permissions. If outputFile
// is empty or opening/creating the file fails, it logs a warning and falls back to os.Stdout.
func GetWriter(ctx context.Context, outputFile string) *os.File {
	if outputFile != "" {
		outputDir, _ := filepath.Split(outputFile)
		if outputDir == "" {
			outputDir = "."
		}
		if err := os.MkdirAll(outputDir, outputDirPerm); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := openFileForPrinter(outputFile)
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
	return getWriterNoFallback(outputFile, openFileForWrite)
}

// GetPrinterWriterNoFallback is GetWriterNoFallback for the result printers:
// the file's existing content is kept until the printer calls PrepareOutput.
func GetPrinterWriterNoFallback(outputFile string) (*os.File, error) {
	return getWriterNoFallback(outputFile, openFileForPrinter)
}

func getWriterNoFallback(outputFile string, open func(string) (*os.File, error)) (*os.File, error) {
	// filepath.Dir would clean "link/../" lexically and create a different
	// directory than the one the file is opened in; keep the path as given.
	outputDir, _ := filepath.Split(outputFile)
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, outputDirPerm); err != nil {
		return nil, fmt.Errorf("create output directory for %q: %w", outputFile, err)
	}
	f, err := open(outputFile)
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
		outputDir, _ := filepath.Split(outputFile)
		if outputDir == "" {
			outputDir = "."
		}
		if err := os.MkdirAll(outputDir, outputDirPerm); err == nil {
			if f, err := openFileForPrinter(outputFile); err == nil {
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
		if tmp, tmpErr := os.CreateTemp("", tempPattern); tmpErr == nil {
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
