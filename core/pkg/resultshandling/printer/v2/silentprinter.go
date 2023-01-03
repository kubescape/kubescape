package printer

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
)

type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
}
