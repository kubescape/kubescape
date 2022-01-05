package v2

import (
	"net/url"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
	"github.com/gofrs/uuid"
)

func (report *ReportEventReceiver) initEventReceiverURL() {
	urlObj := url.URL{}

	urlObj.Scheme = "https"
	urlObj.Host = getter.GetArmoAPIConnector().GetReportReceiverURL()
	urlObj.Path = "/k8s/postureReport"
	q := urlObj.Query()
	q.Add("customerGUID", uuid.FromStringOrNil(report.customerGUID).String())
	q.Add("clusterName", report.clusterName)

	urlObj.RawQuery = q.Encode()

	report.eventReceiverURL = &urlObj
}

func hostToString(host *url.URL, reportID string) string {
	q := host.Query()
	q.Add("reportID", reportID) // TODO - do we add the reportID?
	host.RawQuery = q.Encode()
	return host.String()
}

func setSubReport(postureReport *reporthandlingv2.PostureReport) *reporthandlingv2.PostureReport {
	return &reporthandlingv2.PostureReport{
		CustomerGUID:         postureReport.CustomerGUID,
		ClusterName:          postureReport.ClusterName,
		ReportID:             postureReport.ReportID,
		ReportGenerationTime: postureReport.ReportGenerationTime,
	}
}
func iMetaToResource(obj workloadinterface.IMetadata) *reporthandling.Resource {
	return &reporthandling.Resource{
		ResourceID: obj.GetID(),
		Object:     obj.GetObject(),
	}
}
