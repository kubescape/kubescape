package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	v1 "github.com/kubescape/backend/pkg/server/v1"
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

const MAX_REPORT_SIZE = 2097152 // 2 MB

type SubmitContext string

const (
	SubmitContextScan       SubmitContext = "scan"
	SubmitContextRepository SubmitContext = "repository"
)

var _ reporter.IReport = &ReportEventReceiver{}

type ReportEventReceiver struct {
	reportTime         time.Time
	httpClient         *http.Client
	tenantConfig       cautils.ITenantConfig
	eventReceiverURL   *url.URL
	message            string
	reportID           string
	submitContext      SubmitContext
	accountIdGenerated bool
}

func NewReportEventReceiver(tenantConfig cautils.ITenantConfig, reportID string, submitContext SubmitContext) *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient:    &http.Client{},
		tenantConfig:  tenantConfig,
		reportID:      reportID,
		submitContext: submitContext,
	}
}

func (report *ReportEventReceiver) Submit(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "reportEventReceiver.Submit")
	defer span.End()
	report.reportTime = time.Now().UTC()

	if report.GetAccountID() == "" {
		accountID := report.tenantConfig.GenerateAccountID()
		report.accountIdGenerated = true
		logger.L().Debug("generated account ID", helpers.String("account ID", accountID))
	}

	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Cluster && report.GetClusterName() == "" {
		logger.L().Ctx(ctx).Error("failed to publish results because the cluster name is Unknown. If you are scanning YAML files the results are not submitted to the Kubescape SaaS")
		return nil
	}

	if err := report.prepareReport(opaSessionObj); err != nil {
		return fmt.Errorf("failed to submit scan results. url: '%s', reason: %s", report.eventReceiverURL, err.Error())
	}

	logger.L().Debug("", helpers.String("account ID", report.GetAccountID()))

	return nil
}

func (report *ReportEventReceiver) SetTenantConfig(tenantConfig cautils.ITenantConfig) {
	report.tenantConfig = tenantConfig
}

func (report *ReportEventReceiver) GetAccountID() string {
	return report.tenantConfig.GetAccountID()
}

func (report *ReportEventReceiver) GetClusterName() string {
	return cautils.AdoptClusterName(report.tenantConfig.GetContextName()) // clean cluster name
}

func (report *ReportEventReceiver) prepareReport(opaSessionObj *cautils.OPASessionObj) error {
	// The backend for Kubescape expects scanning targets to be either
	// Clusters or Files, not other types we support (GitLocal, Directory
	// etc). So, to submit a compatible report to the backend, we have to
	// override the scanning target, submit the report and then restore the
	// original value.
	originalScanningTarget := opaSessionObj.Metadata.ScanMetadata.ScanningTarget

	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget != reporthandlingv2.Cluster {
		opaSessionObj.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
		defer func() {
			opaSessionObj.Metadata.ScanMetadata.ScanningTarget = originalScanningTarget
		}()
	}

	report.initEventReceiverURL()
	host := hostToString(report.eventReceiverURL, report.reportID)

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	return report.sendResources(host, opaSessionObj)
}

func (report *ReportEventReceiver) sendResources(host string, opaSessionObj *cautils.OPASessionObj) error {
	splittedPostureReport := report.setSubReport(opaSessionObj)

	counter := 0
	reportCounter := 0

	if err := report.setResources(splittedPostureReport, opaSessionObj.AllResources, opaSessionObj.ResourceSource, opaSessionObj.ResourcesResult, &counter, &reportCounter, host); err != nil {
		return err
	}

	if err := report.setResults(splittedPostureReport, opaSessionObj.ResourcesResult, opaSessionObj.AllResources, opaSessionObj.ResourceSource, opaSessionObj.ResourcesPrioritized, &counter, &reportCounter, host); err != nil {
		return err
	}

	return report.sendReport(host, splittedPostureReport, reportCounter, true)
}

func (report *ReportEventReceiver) setResults(reportObj *reporthandlingv2.PostureReport, results map[string]resourcesresults.Result, allResources map[string]workloadinterface.IMetadata, resourcesSource map[string]reporthandling.Source, prioritizedResources map[string]prioritization.PrioritizedResource, counter, reportCounter *int, host string) error {
	for _, v := range results {
		// set result.RawResource
		resourceID := v.GetResourceID()
		if _, ok := allResources[resourceID]; !ok {
			continue
		}
		resource := reporthandling.NewResourceIMetadata(allResources[resourceID])
		if r, ok := resourcesSource[resourceID]; ok {
			resource.SetSource(&r)
		}
		v.RawResource = resource

		// set result.PrioritizedResource
		if results, ok := prioritizedResources[resourceID]; ok {
			v.PrioritizedResource = &results
		}

		r, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.GetResourceID(), err)
		}

		if *counter+len(r) >= MAX_REPORT_SIZE && len(reportObj.Results) > 0 {

			// send report
			if err := report.sendReport(host, reportObj, *reportCounter, false); err != nil {
				return err
			}
			*reportCounter++

			// delete results
			reportObj.Results = []resourcesresults.Result{}
			reportObj.Resources = []reporthandling.Resource{}

			// restart counter
			*counter = 0
		}

		*counter += len(r)
		reportObj.Results = append(reportObj.Results, v)
	}
	return nil
}

func (report *ReportEventReceiver) setResources(reportObj *reporthandlingv2.PostureReport, allResources map[string]workloadinterface.IMetadata, resourcesSource map[string]reporthandling.Source, results map[string]resourcesresults.Result, counter, reportCounter *int, host string) error {
	for resourceID, v := range allResources {
		/*

			// process only resources which have no result because these resources will be sent on the result object
			if _, hasResult := results[resourceID]; hasResult {
				continue
			}

		*/

		resource := reporthandling.NewResourceIMetadata(v)
		if r, ok := resourcesSource[resourceID]; ok {
			resource.SetSource(&r)
		}
		r, err := json.Marshal(resource)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", resourceID, err)
		}

		if *counter+len(r) >= MAX_REPORT_SIZE && len(reportObj.Resources) > 0 {

			// send report
			if err := report.sendReport(host, reportObj, *reportCounter, false); err != nil {
				return err
			}
			*reportCounter++

			// delete resources
			reportObj.Resources = []reporthandling.Resource{}
			reportObj.Results = []resourcesresults.Result{}

			// restart counter
			*counter = 0
		}

		*counter += len(r)
		reportObj.Resources = append(reportObj.Resources, *resource)
	}
	return nil
}

func (report *ReportEventReceiver) sendReport(host string, postureReport *reporthandlingv2.PostureReport, counter int, isLastReport bool) error {
	postureReport.PaginationInfo = apis.PaginationMarks{
		ReportNumber: counter,
		IsLastReport: isLastReport,
	}
	reqBody, err := json.Marshal(postureReport)
	if err != nil {
		return fmt.Errorf("in 'sendReport' failed to json.Marshal, reason: %v", err)
	}
	strResponse, err := getter.HttpPost(report.httpClient, host, nil, reqBody)
	if err != nil {
		// in case of error, we need to revert the generated account ID
		// otherwise the next run will fail using a non existing account ID
		if report.accountIdGenerated {
			report.tenantConfig.DeleteAccountID()
		}

		return fmt.Errorf("%s, %v:%s", host, err, strResponse)
	}

	// message is taken only from last report
	if strResponse != "" && isLastReport {
		response := v1.PostureReportResponse{}
		if unmarshalErr := json.Unmarshal([]byte(strResponse), &response); unmarshalErr != nil {
			logger.L().Error("failed to unmarshal server response")
		} else {
			report.setMessage(response.Message)
		}
	}

	return err
}

func (report *ReportEventReceiver) setMessage(message string) {
	report.message = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n" + message
}

func (report *ReportEventReceiver) DisplayMessage() {

	// print if logger level is lower than warning (debug/info)
	if report.message != "" && helpers.ToLevel(logger.L().GetLevel()) < helpers.WarningLevel {
		txt := "View results"
		cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n%s\n", txt))

		cautils.SimpleDisplay(os.Stderr, strings.Repeat("─", len(txt)))

		cautils.SimpleDisplay(os.Stderr, fmt.Sprintf("\n\n%s\n\n", report.message))
	}
}
