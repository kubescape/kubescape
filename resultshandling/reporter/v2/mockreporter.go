package v2

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
)

const NO_SUBMIT_QUERY = "utm_source=GitHub&utm_medium=CLI&utm_campaign=no_submit"

type ReportMock struct {
	query string
}

func NewReportMock(query string) *ReportMock {
	return &ReportMock{
		query: query,
	}
}
func (reportMock *ReportMock) ActionSendReport(opaSessionObj *cautils.OPASessionObj) error {
	return nil
}

func (reportMock *ReportMock) SetCustomerGUID(customerGUID string) {
}

func (reportMock *ReportMock) SetClusterName(clusterName string) {
}

func (reportMock *ReportMock) DisplayReportURL() {
	u := fmt.Sprintf("https://%s/account/login", getter.GetArmoAPIConnector().GetFrontendURL())
	if reportMock.query != "" {
		u += fmt.Sprintf("?%s", reportMock.query)
	}
	sep := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	message := sep + "\n"
	message += "Scan results have not been submitted." + "\n"
	message += "Sign up for free: "
	message += u + "\n"
	message += sep + "\n"
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n%s\n", message))
}
