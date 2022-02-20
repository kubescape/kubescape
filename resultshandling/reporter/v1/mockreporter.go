package v1

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
)

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

func (reportMock *ReportMock) DisplayReportURL() {
	message := fmt.Sprintf("\nScan results have not been submitted.\nYou can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more by registering here: https://%s/cli-signup \n", getter.GetArmoAPIConnector().GetFrontendURL())
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n%s\n", message))
}
