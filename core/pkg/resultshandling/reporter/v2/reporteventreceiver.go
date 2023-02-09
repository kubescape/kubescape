package reporter

import (
	"context"
	"fmt"
	"os"

	"github.com/armosec/armoapi-go/apis"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"go.opentelemetry.io/otel"
)

const maxReportSize = 2 * 1024 * 1024

var _ reporter.IReport = &ReportEventReceiver{}

type (
	// ReportEventReceiver posts a posture report to the KS Cloud SaaS.
	//
	// Large reports are paginated in chunks of about 2MB.
	ReportEventReceiver struct {
		*getter.KSCloudAPI

		clusterName        string
		customerAdminEMail string
		reportID           string
		submitContext      SubmitContext
		posted             bool
		bytesCount         int
		postedCount        int
		maxReportSize      int
	}

	// results used to iteratively construct the chunked report
	results struct {
		reportObj            *reporthandlingv2.PostureReport
		allResources         map[string]workloadinterface.IMetadata
		resourcesSource      map[string]reporthandling.Source
		results              map[string]resourcesresults.Result
		prioritizedResources map[string]prioritization.PrioritizedResource
	}
)

// NewReportEventReceiver builds an IReport-capable object to send reports for a given submit context (scan, rbac, repository).
func NewReportEventReceiver(tenantConfig *cautils.ConfigObj, reportID string, submitContext SubmitContext) *ReportEventReceiver {
	report := &ReportEventReceiver{
		KSCloudAPI:         getter.GetKSCloudAPIConnector(),
		clusterName:        tenantConfig.ClusterName,
		customerAdminEMail: tenantConfig.CustomerAdminEMail,
		reportID:           reportID,
		submitContext:      submitContext,
		maxReportSize:      maxReportSize,
	}

	report.SetAccountID(tenantConfig.AccountID)
	report.SetInvitationToken(tenantConfig.Token)

	return report
}

func (report *ReportEventReceiver) SetCustomerGUID(customerGUID string) {
	report.SetAccountID(customerGUID)
}

func (report *ReportEventReceiver) SetClusterName(clusterName string) {
	report.clusterName = cautils.AdoptClusterName(clusterName) // clean cluster name
}

// DisplayReportURL indicates the URL of the report on the SaaS UI.
//
// This message is displayed only if the report has been posted.
func (report *ReportEventReceiver) DisplayReportURL() {
	if !report.posted {
		return
	}

	// print if logger level is lower than warning (debug/info)
	if helpers.ToLevel(logger.L().GetLevel()) >= helpers.WarningLevel {
		return
	}

	cautils.InfoTextDisplay(
		os.Stderr,
		fmt.Sprintf("\n\n%s\n\n", report.generateMessage()),
	)
}

// GetURL yields the URL to view the posted reports for the context of this report generation.
func (report *ReportEventReceiver) GetURL() string {
	if report.customerAdminEMail == "" && report.GetInvitationToken() != "" {
		return report.ViewSignURL()
	}

	switch report.submitContext {
	case SubmitContextScan:
		return report.ViewScanURL(report.clusterName)
	case SubmitContextRBAC:
		return report.ViewRBACURL()
	case SubmitContextRepository:
		return report.ViewReportURL(report.reportID)
	default:
		return report.ViewDashboardURL()
	}
}

// Submit to the SaaS a posture report produced by the session.
func (report *ReportEventReceiver) Submit(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "reportEventReceiver.Submit")
	defer span.End()

	if err := report.requiredToSubmit(opaSessionObj); err != nil {
		logger.L().Ctx(ctx).Error(err.Error())

		return nil
	} else {
		logger.L().Ctx(ctx).Debug("submit report",
			helpers.String("account ID", report.GetAccountID()),
			helpers.String("submitContext", report.submitContext.String()),
		)
	}

	if err := report.sendChunkedReport(opaSessionObj); err != nil {
		return errSubmit(report.GetURL(), err)
	}

	report.posted = true

	return nil
}

func (report *ReportEventReceiver) requiredToSubmit(opaSessionObj *cautils.OPASessionObj) error {
	if guid := report.GetAccountID(); guid == "" {
		return ErrRequireAccountID
	}

	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Cluster && report.clusterName == "" {
		return ErrRequireClusterName
	}

	return nil
}

func (report *ReportEventReceiver) sendChunkedReport(opaSessionObj *cautils.OPASessionObj) error {
	// The backend for Kubescape expects scanning targets to be either
	// Clusters or Files, not other types we support (GitLocal, Directory, etc.).
	// To submit a compatible report to the backend, we have to
	// override the scanning target, submit the report and then restore the
	// original value.

	originalScanningTarget := opaSessionObj.Metadata.ScanMetadata.ScanningTarget

	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget != reporthandlingv2.Cluster {
		opaSessionObj.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
		defer func() {
			opaSessionObj.Metadata.ScanMetadata.ScanningTarget = originalScanningTarget
		}()
	}

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	postureReport := report.newPostureReport(opaSessionObj)

	res := results{
		reportObj:            postureReport,
		allResources:         opaSessionObj.AllResources,
		resourcesSource:      opaSessionObj.ResourceSource,
		results:              opaSessionObj.ResourcesResult,
		prioritizedResources: opaSessionObj.ResourcesPrioritized,
	}

	// send chunks with resources first
	if err := report.sendResources(res); err != nil {
		return err
	}

	// send chunks of raw resources, prioritized resources and results
	if err := report.sendResults(res); err != nil {
		return err
	}

	// send remainder
	return report.sendReport(postureReport, true)
}

func (report *ReportEventReceiver) sendResources(in results) error {
	for resourceID, v := range in.allResources {
		resource := reporthandling.NewResourceIMetadata(v)
		if source, ok := in.resourcesSource[resourceID]; ok {
			resource.SetSource(&source)
		}

		r, err := json.Marshal(resource)
		if err != nil {
			return errMarshal(resourceID, err)
		}

		if report.bytesCount+len(r) >= report.maxReportSize && len(in.reportObj.Resources) > 0 {
			// send a report page
			if err := report.sendReport(in.reportObj, false); err != nil {
				return err
			}

			// delete already posted resources
			in.reportObj.Resources = []reporthandling.Resource{}
			in.reportObj.Results = []resourcesresults.Result{}

			// reset counter
			report.bytesCount = 0
		}

		report.bytesCount += len(r)
		in.reportObj.Resources = append(in.reportObj.Resources, *resource)
	}

	return nil
}

func (report *ReportEventReceiver) sendResults(in results) error {
	for _, v := range in.results {
		resourceID := v.GetResourceID()
		if _, ok := in.allResources[resourceID]; !ok {
			// ignore unregistered resources
			continue
		}

		// set raw resource
		resource := reporthandling.NewResourceIMetadata(in.allResources[resourceID])
		if source, ok := in.resourcesSource[resourceID]; ok {
			resource.SetSource(&source)
		}
		v.RawResource = resource

		// set prioritized resource
		if results, ok := in.prioritizedResources[resourceID]; ok {
			v.PrioritizedResource = &results
		}

		r, err := json.Marshal(v)
		if err != nil {
			return errMarshal(resourceID, err)
		}

		if report.bytesCount+len(r) >= report.maxReportSize && len(in.reportObj.Results) > 0 {
			// send a report page
			if err := report.sendReport(in.reportObj, false); err != nil {
				return err
			}

			// delete the already posted results
			in.reportObj.Results = []resourcesresults.Result{}
			in.reportObj.Resources = []reporthandling.Resource{}

			// reset counter
			report.bytesCount = 0
		}

		report.bytesCount += len(r)
		in.reportObj.Results = append(in.reportObj.Results, v)
	}

	return nil
}

// sendReport posts a paginated report.
func (report *ReportEventReceiver) sendReport(postureReport *reporthandlingv2.PostureReport, isLastReport bool) error {
	postureReport.PaginationInfo = apis.PaginationMarks{
		ReportNumber: report.postedCount,
		IsLastReport: isLastReport,
	}
	report.postedCount++

	return report.SubmitReport(postureReport)
}

func (report *ReportEventReceiver) generateMessage() string {
	const (
		sep     = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
		heading = "<< WOW! Now you can see the scan results on the web >>"
		indent  = "   "
	)

	return fmt.Sprintf(
		"%s\n%s%s\n\n%s%s\n%s\n",
		sep,
		indent,
		heading,
		indent,
		report.GetURL(),
		sep,
	)
}

// newPostureReport prepares a posture report for uploading.
func (report *ReportEventReceiver) newPostureReport(opaSessionObj *cautils.OPASessionObj) *reporthandlingv2.PostureReport {
	reportObj := &reporthandlingv2.PostureReport{
		CustomerGUID:         report.GetAccountID(),
		ClusterName:          report.clusterName,
		ReportID:             report.reportID,
		ReportGenerationTime: opaSessionObj.Report.ReportGenerationTime,
		SummaryDetails:       opaSessionObj.Report.SummaryDetails,
		Attributes:           opaSessionObj.Report.Attributes,
		ClusterAPIServerInfo: opaSessionObj.Report.ClusterAPIServerInfo,
	}

	if opaSessionObj.Metadata != nil {
		reportObj.Metadata = *opaSessionObj.Metadata
		if opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
			reportObj.ClusterCloudProvider = opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudProvider // DEPRECATED - left here as a fallback
		}
	}

	return reportObj
}
