package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
)

var INDENT = "   "

const (
	PrettyFormat      string = "pretty-printer"
	JsonFormat        string = "json"
	JunitResultFormat string = "junit"
	PrometheusFormat  string = "prometheus"
	PdfFormat         string = "pdf"
	HtmlFormat        string = "html"
	SARIFFormat       string = "sarif"
)

type IPrinter interface {
	PrintNextSteps()
	ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData)
	SetWriter(ctx context.Context, outputFile string)
	Score(score float32)
}

func GetWriter(ctx context.Context, outputFile string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), os.ModePerm); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := os.Create(outputFile)
		if err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}

// GetWriterNoStdoutFallback opens outputFile for writing for formats whose
// output (binary, markup) would corrupt a TTY if dumped to stdout. On any
// failure to open the requested file it falls back to a uniquely-named file
// under os.TempDir() using tempPattern (e.g. "kubescape-report-*.pdf"). If
// that fails it tries os.DevNull, then a pipe-based sink as a last resort.
// It never returns os.Stdout.
func GetWriterNoStdoutFallback(ctx context.Context, outputFile, tempPattern string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), os.ModePerm); err == nil {
			if f, err := os.Create(outputFile); err == nil {
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
