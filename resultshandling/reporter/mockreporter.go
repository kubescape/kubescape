package reporter

import "github.com/armosec/kubescape/cautils"

type ReportMock struct {
}

func NewReportMock() *ReportMock {
	return &ReportMock{}
}
func (reportMock *ReportMock) ActionSendReport(opaSessionObj *cautils.OPASessionObj) error {
	return nil
}

func (reportMock *ReportMock) SetCustomerGUID(customerGUID string) {
}

func (reportMock *ReportMock) SetClusterName(clusterName string) {
}
