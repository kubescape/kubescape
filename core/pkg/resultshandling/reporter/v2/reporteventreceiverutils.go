package v2

import (
	"net/url"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
	"github.com/google/uuid"
)

func (report *ReportEventReceiver) initEventReceiverURL() {
	urlObj := url.URL{}

	urlObj.Scheme = "https"
	urlObj.Host = getter.GetArmoAPIConnector().GetReportReceiverURL()
	urlObj.Path = "/k8s/v2/postureReport"

	q := urlObj.Query()
	q.Add("customerGUID", uuid.MustParse(report.customerGUID).String())
	q.Add("clusterName", report.clusterName)

	urlObj.RawQuery = q.Encode()

	report.eventReceiverURL = &urlObj
}

func hostToString(host *url.URL, reportID string) string {
	q := host.Query()
	q.Add("reportGUID", reportID) // TODO - do we add the reportID?
	host.RawQuery = q.Encode()
	return host.String()
}

func (report *ReportEventReceiver) setSubReport(opaSessionObj *cautils.OPASessionObj) *reporthandlingv2.PostureReport {
	return &reporthandlingv2.PostureReport{
		CustomerGUID:         report.customerGUID,
		ClusterName:          report.clusterName,
		ReportID:             report.reportID,
		ReportGenerationTime: opaSessionObj.Report.ReportGenerationTime,
		SummaryDetails:       opaSessionObj.Report.SummaryDetails,
		Attributes:           opaSessionObj.Report.Attributes,
		ClusterCloudProvider: opaSessionObj.Report.ClusterCloudProvider,
		ClusterAPIServerInfo: opaSessionObj.Report.ClusterAPIServerInfo,
		Metadata:             *opaSessionObj.Metadata,
	}
}
func iMetaToResource(obj workloadinterface.IMetadata) *reporthandling.Resource {
	return &reporthandling.Resource{
		ResourceID: obj.GetID(),
		Object:     obj.GetObject(),
	}
}
