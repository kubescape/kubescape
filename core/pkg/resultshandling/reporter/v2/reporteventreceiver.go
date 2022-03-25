package v2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"

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
	// if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reporthandlingv2.Cluster && report.clusterName == "" {
	if report.clusterName == "" {
		logger.L().Warning("failed to publish results because the cluster name is Unknown. If you are scanning YAML files the results are not submitted to the Kubescape SaaS")
		return nil
	}

	err := report.prepareReport(opaSessionObj)
	if err == nil {
		report.generateMessage()
	} else {
		logger.L().Debug(err.Error()) // print original error only in debug mode
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

	if report.customerAdminEMail != "" || report.token == "" { // data has been submitted
		u.Path = fmt.Sprintf("configuration-scanning/%s", report.clusterName)
	} else {
		u.Path = "account/sign-up"
		q := u.Query()
		q.Add("invitationToken", report.token)
		q.Add("customerGUID", report.customerGUID)

		u.RawQuery = q.Encode()
	}
	return u.String()

}
func (report *ReportEventReceiver) sendResources(host string, opaSessionObj *cautils.OPASessionObj) error {
	splittedPostureReport := report.setSubReport(opaSessionObj)
	counter := 0
	reportCounter := 0

	for _, v := range opaSessionObj.Report.Resources {
		r, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.ResourceID, err)
		}

		if counter+len(r) >= MAX_REPORT_SIZE && len(splittedPostureReport.Resources) > 0 {

			// send report
			if err := report.sendReport(host, splittedPostureReport, reportCounter, false); err != nil {
				return err
			}
			reportCounter++

			// delete resources
			splittedPostureReport.Resources = []reporthandling.Resource{}
			splittedPostureReport.Results = []resourcesresults.Result{}

			// restart counter
			counter = 0
		}

		counter += len(r)
		splittedPostureReport.Resources = append(splittedPostureReport.Resources, v)
	}

	for _, v := range opaSessionObj.Report.Results {
		r, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.GetResourceID(), err)
		}

		if counter+len(r) >= MAX_REPORT_SIZE && len(splittedPostureReport.Results) > 0 {

			// send report
			if err := report.sendReport(host, splittedPostureReport, reportCounter, false); err != nil {
				return err
			}
			reportCounter++

			// delete results
			splittedPostureReport.Results = []resourcesresults.Result{}
			splittedPostureReport.Resources = []reporthandling.Resource{}

			// restart counter
			counter = 0
		}

		counter += len(r)
		splittedPostureReport.Results = append(splittedPostureReport.Results, v)
	}

	return report.sendReport(host, splittedPostureReport, reportCounter, true)
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
