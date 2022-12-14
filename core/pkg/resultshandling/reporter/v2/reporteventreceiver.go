package reporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/armosec/armoapi-go/apis"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

const MAX_REPORT_SIZE = 2097152 // 2 MB

type SubmitContext string

const (
	SubmitContextScan       SubmitContext = "scan"
	SubmitContextRBAC       SubmitContext = "rbac"
	SubmitContextRepository SubmitContext = "repository"
)

type ReportEventReceiver struct {
	httpClient         *http.Client
	clusterName        string
	customerGUID       string
	eventReceiverURL   *url.URL
	token              string
	customerAdminEMail string
	message            string
	reportID           string
	submitContext      SubmitContext
}

func NewReportEventReceiver(tenantConfig *cautils.ConfigObj, reportID string, submitContext SubmitContext) *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient:         &http.Client{},
		clusterName:        tenantConfig.ClusterName,
		customerGUID:       tenantConfig.AccountID,
		token:              tenantConfig.Token,
		customerAdminEMail: tenantConfig.CustomerAdminEMail,
		reportID:           reportID,
		submitContext:      submitContext,
	}
}

func (report *ReportEventReceiver) Submit(opaSessionObj *cautils.OPASessionObj) error {

	if report.customerGUID == "" {
		logger.L().Warning("failed to publish results. Reason: Unknown accout ID. Run kubescape with the '--account <account ID>' flag. Contact ARMO team for more details")
		return nil
	}
	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Cluster && report.clusterName == "" {
		logger.L().Warning("failed to publish results because the cluster name is Unknown. If you are scanning YAML files the results are not submitted to the Kubescape SaaS")
		return nil
	}

	err := report.prepareReport(opaSessionObj)
	if err == nil {
		report.generateMessage()
	} else {
		err = fmt.Errorf("failed to submit scan results. url: '%s', reason: %s", report.GetURL(), err.Error())
	}

	logger.L().Debug("", helpers.String("account ID", report.customerGUID))

	return err
}

func (report *ReportEventReceiver) SetCustomerGUID(customerGUID string) {
	report.customerGUID = customerGUID
}

func (report *ReportEventReceiver) SetClusterName(clusterName string) {
	report.clusterName = cautils.AdoptClusterName(clusterName) // clean cluster name
}

func (report *ReportEventReceiver) prepareReport(opaSessionObj *cautils.OPASessionObj) error {
	// All scans whose target is not a cluster, currently their target is a file, which is what the backend expects
	// (e.g. local-git, directory, etc)
	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget != reporthandlingv2.Cluster {
		opaSessionObj.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
	}

	report.initEventReceiverURL()
	host := hostToString(report.eventReceiverURL, report.reportID)

	cautils.StartSpinner()

	// send resources
	err := report.sendResources(host, opaSessionObj)

	cautils.StopSpinner()
	return err
}

func (report *ReportEventReceiver) GetURL() string {
	u := url.URL{}
	u.Host = getter.GetKSCloudAPIConnector().GetCloudUIURL()

	parseHost(&u)
	report.addPathURL(&u)

	q := u.Query()
	q.Add("utm_source", "GitHub")
	q.Add("utm_medium", "CLI")
	q.Add("utm_campaign", "Submit")

	u.RawQuery = q.Encode()

	return u.String()

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
			return fmt.Errorf("expected to find raw resource object for '%s'", resourceID)
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
	msg, err := getter.HttpPost(report.httpClient, host, nil, reqBody)
	if err != nil {
		return fmt.Errorf("%s, %v:%s", host, err, msg)
	}
	return err
}

func (report *ReportEventReceiver) generateMessage() {
	report.message = ""

	sep := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
	report.message = sep
	report.message += "   << WOW! Now you can see the scan results on the web >>\n\n"
	report.message += fmt.Sprintf("   %s\n", report.GetURL())
	report.message += sep

}

func (report *ReportEventReceiver) DisplayReportURL() {
	if report.message != "" {
		cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n\n%s\n\n", report.message))
	}
}

func (report *ReportEventReceiver) addPathURL(urlObj *url.URL) {
	if report.customerAdminEMail != "" || report.token == "" { // data has been submitted
		switch report.submitContext {
		case SubmitContextScan:
			urlObj.Path = fmt.Sprintf("configuration-scanning/%s", report.clusterName)
		case SubmitContextRBAC:
			urlObj.Path = "rbac-visualizer"
		case SubmitContextRepository:
			urlObj.Path = fmt.Sprintf("repository-scanning/%s", report.reportID)
		default:
			urlObj.Path = "dashboard"
		}
		return
	}
	urlObj.Path = "account/sign-up"

	q := urlObj.Query()
	q.Add("invitationToken", report.token)
	q.Add("customerGUID", report.customerGUID)
	urlObj.RawQuery = q.Encode()

}
