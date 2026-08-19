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

	w := os.Stdout
	if diffInfo.Output != "" {
		w, err = printer.GetWriterNoFallback(diffOutputPath(diffInfo.Format, diffInfo.Output))
		if err != nil {
			return 0, fmt.Errorf("opening diff output: %w", err)
		}
		defer func() {
			err = closeDiffOutput(w, err)
		}()
	}

	switch diffInfo.Format {
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

func diffOutputPath(format, outputFile string) string {
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		return ""
	}
	if format == printer.PrettyFormat {
		return outputFile
	}
	ext, ok := printer.FormatOutputExt[format]
	if !ok || ext == "" {
		return outputFile
	}
	if ext == printer.YamlOutputExt && strings.HasSuffix(outputFile, ".yml") {
		return outputFile
	}
	if printer.HasOutputExt(outputFile, ext) {
		return outputFile
	}
	return outputFile + ext
}
