package printer

import (
	"github.com/armosec/kubescape/cautils"
)

type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
}
