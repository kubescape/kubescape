package reporter

import (
	"net/url"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/gofrs/uuid"
)

func (report *ReportEventReceiver) initEventReceiverURL() *url.URL {
	urlObj := url.URL{}

	urlObj.Scheme = "https"
	urlObj.Host = getter.GetArmoAPIConnector().GetReportReceiverURL()
	urlObj.Path = "/k8s/postureReport"
	q := urlObj.Query()
	q.Add("customerGUID", uuid.FromStringOrNil(report.customerGUID).String())
	q.Add("clusterName", report.clusterName)

	urlObj.RawQuery = q.Encode()

	return &urlObj
}

func hostToString(host *url.URL, reportID string) string {
	q := host.Query()
	q.Add("reportID", reportID) // TODO - do we add the reportID?
	host.RawQuery = q.Encode()
	return host.String()
}
