package reporter

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

type IReport interface {
	Submit(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
	DisplayReportURL()
	GetURL() string
}
