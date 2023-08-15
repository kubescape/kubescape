package reporter

import (
	"net/url"

	"github.com/google/uuid"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func (report *ReportEventReceiver) initEventReceiverURL() {
	urlObj := url.URL{}
	urlObj.Host = getter.GetKSCloudAPIConnector().GetCloudReportURL()
	parseHost(&urlObj)

	urlObj.Path = "/k8s/v2/postureReport"
	q := urlObj.Query()
	q.Add("customerGUID", uuid.MustParse(report.GetAccountID()).String())
	q.Add("contextName", report.GetClusterName())
	q.Add("clusterName", report.GetClusterName()) // deprecated

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
	reportObj := &reporthandlingv2.PostureReport{
		CustomerGUID:          report.GetAccountID(),
		ClusterName:           report.GetClusterName(),
		ReportID:              report.reportID,
		ReportGenerationTime:  report.reportTime,
		SummaryDetails:        opaSessionObj.Report.SummaryDetails,
		Attributes:            opaSessionObj.Report.Attributes,
		ClusterAPIServerInfo:  opaSessionObj.Report.ClusterAPIServerInfo,
		CustomerGUIDGenerated: report.accountIdGenerated,
	}
	if opaSessionObj.Metadata != nil {
		reportObj.Metadata = *opaSessionObj.Metadata
		if opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
			reportObj.ClusterCloudProvider = opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudProvider // DEPRECATED - left here as fallback
		}
	}
	return reportObj
}
