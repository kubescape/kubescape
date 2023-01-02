package reporter

import (
	"fmt"
	"net/url"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

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
	u := url.URL{}
	u.Host = getter.GetKSCloudAPIConnector().GetCloudUIURL()
	u.Path = "account/sign-up"

	parseHost(&u)

	q := u.Query()
	q.Add("utm_source", "GitHub")
	q.Add("utm_medium", "CLI")
	q.Add("utm_campaign", "Submit")

	u.RawQuery = q.Encode()

	return u.String()
}

func (reportMock *ReportMock) DisplayReportURL() {

	sep := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	message := sep + "\n"
	message += "Scan results have not been submitted: " + reportMock.message + "\n"
	message += "For more details: " + reportMock.GetURL() + "\n"
	message += sep + "\n"
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n%s\n", message))
}
