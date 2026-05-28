package core

import (
	"context"
	"fmt"
	"os"

	"github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

func (ks *Kubescape) Diff(diffInfo *metav1.DiffInfo) error {
	cs, err := diff.Compute(diffInfo.BaseFile, diffInfo.HeadFile)
	if err != nil {
		return err
	}

	w := printer.GetWriter(context.Background(), diffInfo.Output)
	if w != os.Stdout {
		defer w.Close()
	}

	switch diffInfo.Format {
	case "json":
		if err := diff.PrintJSON(w, cs); err != nil {
			return fmt.Errorf("writing JSON diff: %w", err)
		}
	default:
		diff.PrintPretty(w, cs)
	}

	if diffInfo.FailOnNew {
		filtered := diff.FilterBySeverity(cs.New, diffInfo.SeverityThreshold)
		if len(filtered) > 0 {
			logger.L().Fatal(fmt.Sprintf("found %d new failure(s) at or above severity threshold %q",
				len(filtered), severityLabel(diffInfo.SeverityThreshold)))
		}
	}

	return nil
}

func severityLabel(s string) string {
	if s == "" {
		return "all"
	}
	return s
}
