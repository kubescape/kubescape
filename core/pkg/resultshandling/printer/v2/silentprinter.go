package printer

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
)

var _ printer.IPrinter = &SilentPrinter{}

// SilentPrinter is a printer that does not print anything
type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj) {
}

func (silentPrinter *SilentPrinter) SetWriter(ctx context.Context, outputFile string) {
}

func (silentPrinter *SilentPrinter) Score(score float32) {
}
