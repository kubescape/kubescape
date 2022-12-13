package reporter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

const NO_SUBMIT_QUERY = "utm_source=GitHub&utm_medium=CLI&utm_campaign=no_submit"

type ReportMock struct {
	query   string
	message string
}

func NewReportMock(query, message string) *ReportMock {
	return &ReportMock{
		query:   query,
		message: message,
	}
}
func (reportMock *ReportMock) Submit(opaSessionObj *cautils.OPASessionObj) error {
	return nil
}

func (reportMock *ReportMock) SetCustomerGUID(customerGUID string) {
}

func (reportMock *ReportMock) SetClusterName(clusterName string) {
}

func (reportMock *ReportMock) GetURL() string {
	u := fmt.Sprintf("https://%s/account/sign-up", getter.GetKSCloudAPIConnector().GetCloudUIURL())
	if reportMock.query != "" {
		u += fmt.Sprintf("?%s", reportMock.query)
	}
	return u
}

func (reportMock *ReportMock) DisplayReportURL() {

	sep := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	message := sep + "\n"
	message += "Scan results have not been submitted: " + reportMock.message + "\n"
	if reportMock.query != "" {
		message += "For more details: " + reportMock.query + "\n"
	}
	message += sep + "\n"
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n%s\n", message))
}
