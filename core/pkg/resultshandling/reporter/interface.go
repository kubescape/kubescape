package reporter

import (
	"context"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

type IReport interface {
	Submit(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error
	SetTenantConfig(tenantConfig cautils.ITenantConfig)
	DisplayMessage()
}
