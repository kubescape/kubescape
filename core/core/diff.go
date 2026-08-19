package core

import (
	"errors"
	"fmt"
	"io"
	"os"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
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
		w, err = printer.GetWriterNoFallback(diffInfo.Output)
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
