package reporter

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
)

var _ reporter.IReport = &ReportMock{}

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
func (reportMock *ReportMock) Submit(_ context.Context, opaSessionObj *cautils.OPASessionObj) error {
	return nil
}

func (reportMock *ReportMock) SetTenantConfig(tenantConfig cautils.ITenantConfig) {
}

func (reportMock *ReportMock) GetURL() string {
	u, err := url.Parse(reportMock.query)
	if err != nil || u.String() == "" {
		return ""
	}

	return u.String()
}

func (reportMock *ReportMock) DisplayMessage() {
	if m := reportMock.strToDisplay(); m != "" {
		cautils.InfoTextDisplay(os.Stderr, m)
	}
}

func (reportMock *ReportMock) strToDisplay() string {
	if reportMock.message == "" {
		return ""
	}

	sep := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	message := sep + "\n"
	message += "Scan results have not been submitted: " + reportMock.message + "\n"
	if link := reportMock.GetURL(); link != "" {
		message += "For more details: " + link + "\n"
	}
	message += sep + "\n"
	return fmt.Sprintf("\n%s\n", message)
}
