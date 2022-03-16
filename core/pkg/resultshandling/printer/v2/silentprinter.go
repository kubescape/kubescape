package v2

import (
	"github.com/armosec/kubescape/core/cautils"
)

type SilentPrinter struct {
}

func (silentPrinter *SilentPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
}
