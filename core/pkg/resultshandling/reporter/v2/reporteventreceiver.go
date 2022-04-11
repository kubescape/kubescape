package v2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"

	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
)

const MAX_REPORT_SIZE = 2097152 // 2 MB

type ReportEventReceiver struct {
	httpClient         *http.Client
	clusterName        string
	customerGUID       string
	eventReceiverURL   *url.URL
	token              string
	customerAdminEMail string
	message            string
	reportID           string
}

func NewReportEventReceiver(tenantConfig *cautils.ConfigObj, reportID string) *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient:         &http.Client{},
		clusterName:        tenantConfig.ClusterName,
		customerGUID:       tenantConfig.AccountID,
		token:              tenantConfig.Token,
		customerAdminEMail: tenantConfig.CustomerAdminEMail,
		reportID:           reportID,
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

		err = fmt.Errorf("failed to submit scan results. url: '%s'", report.GetURL())
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
	u.Scheme = "https"
	u.Host = getter.GetArmoAPIConnector().GetFrontendURL()

	q := u.Query()

	if report.customerAdminEMail != "" || report.token == "" { // data has been submitted
		u.Path = fmt.Sprintf("configuration-scanning/%s", report.clusterName)
	} else {
		u.Path = "account/sign-up"
		q.Add("invitationToken", report.token)
		q.Add("customerGUID", report.customerGUID)
	}

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
	if err := report.setResources(splittedPostureReport, opaSessionObj.AllResources, opaSessionObj.ResourceSource, &counter, &reportCounter, host); err != nil {
		return err
	}
	if err := report.setResults(splittedPostureReport, opaSessionObj.ResourcesResult, &counter, &reportCounter, host); err != nil {
		return err
	}

	return report.sendReport(host, splittedPostureReport, reportCounter, true)
}
func (report *ReportEventReceiver) setResults(reportObj *reporthandlingv2.PostureReport, results map[string]resourcesresults.Result, counter, reportCounter *int, host string) error {
	for _, v := range results {
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

func (report *ReportEventReceiver) setResources(reportObj *reporthandlingv2.PostureReport, allResources map[string]workloadinterface.IMetadata, resourcesSource map[string]string, counter, reportCounter *int, host string) error {
	for resourceID, v := range allResources {
		resource := reporthandling.NewResourceIMetadata(v)
		if r, ok := resourcesSource[resourceID]; ok {
			resource.SetSource(&reporthandling.Source{Path: r})
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
	postureReport.PaginationInfo = reporthandlingv2.PaginationMarks{
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
