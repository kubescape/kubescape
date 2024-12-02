package printer

import (
	"context"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

var _ printer.IPrinter = &SilentPrinter{}

// SilentPrinter is a printer that does not print anything
type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) PrintNextSteps() {

}

func (silentPrinter *SilentPrinter) PrintImageScan(context.Context, *models.PresenterConfig) {
}

func (silentPrinter *SilentPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
}

func (silentPrinter *SilentPrinter) SetWriter(ctx context.Context, outputFile string) {
}

func (silentPrinter *SilentPrinter) Score(score float32) {
}
