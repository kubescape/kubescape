package core

import (
	"context"
	"fmt"
	"os"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

// Diff writes the diff between the two scan reports and returns the number of new failures at or above the severity threshold; the caller decides whether to exit 1.
func (ks *Kubescape) Diff(diffInfo *metav1.DiffInfo) (int, error) {
	cs, err := diff.Compute(diffInfo.BaseFile, diffInfo.HeadFile)
	if err != nil {
		return 0, err
	}

	w := printer.GetWriter(context.Background(), diffInfo.Output)
	if w != os.Stdout {
		defer w.Close()
	}

	switch diffInfo.Format {
	case printer.JsonFormat:
		if err := diff.PrintJSON(w, cs); err != nil {
			return 0, fmt.Errorf("writing JSON diff: %w", err)
		}
	default:
		diff.PrintPretty(w, cs)
	}

	return len(diff.FilterBySeverity(cs.New, diffInfo.SeverityThreshold)), nil
}
