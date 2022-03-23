package reporter

import "github.com/armosec/kubescape/core/cautils"

type IReport interface {
	ActionSendReport(opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
	DisplayReportURL()
	GetURL() string
}
