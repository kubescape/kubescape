package reporter

import "github.com/armosec/kubescape/cautils"

type IReport interface {
	ActionSendReport(opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
	DisplayReportURL()
}
