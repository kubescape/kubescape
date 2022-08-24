package reporter

import "github.com/kubescape/kubescape/v2/core/cautils"

type IReport interface {
	Submit(opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
	DisplayReportURL()
	GetURL() string
}
