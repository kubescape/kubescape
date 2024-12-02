package reporter

import (
	"github.com/kubescape/kubescape/v3/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

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
