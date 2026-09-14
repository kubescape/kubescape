package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
)

// Diff writes the diff between the two scan reports and returns the number of new or incomparable failures at or above the severity threshold; the caller decides whether to exit 1.
func (ks *Kubescape) Diff(diffInfo *metav1.DiffInfo) (newFailures int, err error) {
	cs, err := diff.ComputeWithOptions(diffInfo.BaseFile, diffInfo.HeadFile, diff.Options{
		Granularity: diff.Granularity(diffInfo.Granularity),
	})
	if err != nil {
		return 0, err
	}

	// A normalized stdout sink writes through the descriptor the process
	// already has; only a file this function opens itself is closed here.
	w := os.Stdout
	if outputFile, explicit := diffOutputPath(diffInfo.Format, diffInfo.Output); explicit {
		w, err = printer.GetWriterNoFallback(outputFile)
		if err != nil {
			return 0, fmt.Errorf("opening diff output: %w", err)
		}
		defer func() {
			err = closeDiffOutput(w, err)
		}()
	}

	switch diffInfo.Format {
	case diff.SummaryJSONFormat:
		if err := diff.PrintSummaryJSON(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing summary JSON diff: %w", err)
		}
	case diff.SummaryYAMLFormat:
		if err := diff.PrintSummaryYAML(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing summary YAML diff: %w", err)
		}
	case diff.SummaryCSVFormat:
		if err := diff.PrintSummaryCSV(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing summary CSV diff: %w", err)
		}
	case printer.JsonFormat:
		if err := diff.PrintJSON(w, cs); err != nil {
			return 0, fmt.Errorf("writing JSON diff: %w", err)
		}
	case printer.YamlFormat:
		if err := diff.PrintYAML(w, cs); err != nil {
			return 0, fmt.Errorf("writing YAML diff: %w", err)
		}
	case printer.SARIFFormat:
		if err := diff.PrintSARIF(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing SARIF diff: %w", err)
		}
	case printer.JunitResultFormat:
		if err := diff.PrintJUnit(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing JUnit diff: %w", err)
		}
	case printer.GitLabSASTFormat:
		if err := diff.PrintGitLabSAST(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing GitLab SAST diff: %w", err)
		}
	case printer.MarkdownFormat:
		if err := diff.PrintMarkdown(w, cs, diffInfo.SeverityThreshold); err != nil {
			return 0, fmt.Errorf("writing Markdown diff: %w", err)
		}
	default:
		if err := diff.PrintPretty(w, cs); err != nil {
			return 0, fmt.Errorf("writing pretty diff: %w", err)
		}
	}

	return len(diff.FilterBySeverity(cs.New, diffInfo.SeverityThreshold)) + len(diff.FilterBySeverity(cs.Incomparable, diffInfo.SeverityThreshold)), nil
}

func closeDiffOutput(closer io.Closer, err error) error {
	if closeErr := closer.Close(); closeErr != nil {
		return errors.Join(err, fmt.Errorf("closing diff output: %w", closeErr))
	}
	return err
}

// diffOutputPath applies the diff output-path rules to an --output value and
// reports whether the result must be opened as a file. It mirrors
// printer.ResolveOutputFile: the well-known sinks skip extension handling, and
// stdout resolves to no file at all so the caller writes through the existing
// os.Stdout descriptor. Reopening the stdout path with os.Create
// (O_RDWR|O_CREATE|O_TRUNC) is not the same thing: it fails with ENXIO when
// stdout is a socket and truncates a regular file stdout was redirected to.
// /dev/null stays a real open, so failing to open it still surfaces as an
// error instead of silently falling back to stdout.
func diffOutputPath(format, outputFile string) (string, bool) {
	if outputFile == "" {
		return "", false
	}
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		// An explicitly requested but blank path stays explicit, so opening
		// it reports the failure rather than writing to stdout.
		return "", true
	}
	if outputFile == os.Stdout.Name() {
		return "", false
	}
	if outputFile == os.DevNull {
		return outputFile, true
	}
	if format == printer.PrettyFormat {
		return outputFile, true
	}
	switch format {
	case diff.SummaryJSONFormat:
		if printer.HasOutputExt(outputFile, printer.JsonOutputExt) {
			return outputFile, true
		}
		return outputFile + printer.JsonOutputExt, true
	case diff.SummaryYAMLFormat:
		if printer.HasOutputExt(outputFile, printer.YamlOutputExt) || printer.HasOutputExt(outputFile, ".yml") {
			return outputFile, true
		}
		return outputFile + printer.YamlOutputExt, true
	case diff.SummaryCSVFormat:
		if printer.HasOutputExt(outputFile, printer.CsvOutputExt) {
			return outputFile, true
		}
		return outputFile + printer.CsvOutputExt, true
	}
	ext, ok := printer.FormatOutputExt[format]
	if !ok || ext == "" {
		return outputFile, true
	}
	if ext == printer.YamlOutputExt && strings.HasSuffix(outputFile, ".yml") {
		return outputFile, true
	}
	if printer.HasOutputExt(outputFile, ext) {
		return outputFile, true
	}
	return outputFile + ext, true
}
