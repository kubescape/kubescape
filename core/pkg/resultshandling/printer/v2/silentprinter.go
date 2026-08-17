package printer

import (
	"context"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

var _ printer.IPrinter = &SilentPrinter{}

// SilentPrinter is a printer that does not print anything
type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) PrintNextSteps() {

}

func (silentPrinter *SilentPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	return nil
}

func (silentPrinter *SilentPrinter) SetWriter(ctx context.Context, outputFile string) error {
	return nil
}

func (silentPrinter *SilentPrinter) Score(score float32) {
}

// CloseWriter is a no-op closer for the silent printer that always returns nil.
func (sp *SilentPrinter) CloseWriter() error { return nil }
