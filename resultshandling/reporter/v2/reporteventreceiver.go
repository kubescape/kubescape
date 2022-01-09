package v2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	uuid "github.com/satori/go.uuid"

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
}

func NewReportEventReceiver(tenantConfig *cautils.ConfigObj) *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient:         &http.Client{},
		clusterName:        tenantConfig.ClusterName,
		customerGUID:       tenantConfig.CustomerGUID,
		token:              tenantConfig.Token,
		customerAdminEMail: tenantConfig.CustomerAdminEMail,
	}
}

func (report *ReportEventReceiver) ActionSendReport(opaSessionObj *cautils.OPASessionObj) error {
	finalizeReport(opaSessionObj)

	if report.customerGUID == "" {
		report.message = "WARNING: Failed to publish results. Reason: Unknown accout ID. Run kubescape with the '--account <account ID>' flag. Contact ARMO team for more details"
		return nil
	}
	if report.clusterName == "" {
		report.message = "WARNING: Failed to publish results. Reason: Unknown cluster name. Run kubescape with the '--cluster <cluster name>' flag"
		return nil
	}
	opaSessionObj.Report.ReportID = uuid.NewV4().String()
	opaSessionObj.Report.CustomerGUID = report.clusterName
	opaSessionObj.Report.ClusterName = report.customerGUID

	if err := report.prepareReport(opaSessionObj.Report); err != nil {
		report.message = err.Error()
	}
	return nil
}

func (report *ReportEventReceiver) SetCustomerGUID(customerGUID string) {
	report.customerGUID = customerGUID
}

func (report *ReportEventReceiver) SetClusterName(clusterName string) {
	report.clusterName = cautils.AdoptClusterName(clusterName) // clean cluster name
}

func (report *ReportEventReceiver) prepareReport(postureReport *reporthandlingv2.PostureReport) error {
	report.initEventReceiverURL()
	host := hostToString(report.eventReceiverURL, postureReport.ReportID)

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	// send framework results
	if err := report.sendReport(host, postureReport); err != nil {
		return err
	}

	// send resources
	if err := report.sendResults(host, postureReport); err != nil {
		return err
	}

	// send resources
	if err := report.sendResources(host, postureReport); err != nil {
		return err
	}
	return nil
}

func (report *ReportEventReceiver) sendResources(host string, postureReport *reporthandlingv2.PostureReport) error {
	splittedPostureReport := setSubReport(postureReport)
	counter := 0

	for _, v := range postureReport.Resources {
		r, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.ResourceID, err)
		}

		if counter+len(r) >= MAX_REPORT_SIZE && len(splittedPostureReport.Resources) > 0 {

			// send report
			if err := report.sendReport(host, splittedPostureReport); err != nil {
				return err
			}

			// delete resources
			splittedPostureReport.Resources = []reporthandlingv2.Resource{}

			// restart counter
			counter = 0
		}

		counter += len(r)
		splittedPostureReport.Resources = append(splittedPostureReport.Resources, v)
	}

	return report.sendReport(host, splittedPostureReport)
}

func (report *ReportEventReceiver) sendResults(host string, postureReport *reporthandlingv2.PostureReport) error {
	splittedPostureReport := setSubReport(postureReport)
	counter := 0

	for _, v := range postureReport.Results {
		r, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.GetResourceID(), err)
		}

		if counter+len(r) >= MAX_REPORT_SIZE && len(splittedPostureReport.Resources) > 0 {

			// send report
			if err := report.sendReport(host, splittedPostureReport); err != nil {
				return err
			}

			// delete results
			splittedPostureReport.Results = []resourcesresults.Result{}

			// restart counter
			counter = 0
		}

		counter += len(r)
		splittedPostureReport.Results = append(splittedPostureReport.Results, v)
	}

	return report.sendReport(host, splittedPostureReport)
}
func (report *ReportEventReceiver) sendReport(host string, postureReport *reporthandlingv2.PostureReport) error {
	splittedPostureReport := setSubReport(postureReport)
	splittedPostureReport.SummaryDetails = postureReport.SummaryDetails

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
	message := "You can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more by registering here:"

	u := url.URL{}
	u.Scheme = "https"
	u.Host = getter.GetArmoAPIConnector().GetFrontendURL()

	if report.customerAdminEMail != "" {
		report.message = fmt.Sprintf("%s %s/risk/%s\n(Account: %s)", message, u.String(), report.clusterName, maskID(report.customerGUID))
		return
	}
	u.Path = "account/sign-up"
	q := u.Query()
	q.Add("invitationToken", report.token)
	q.Add("customerGUID", report.customerGUID)

	u.RawQuery = q.Encode()
	report.message = fmt.Sprintf("%s %s", message, u.String())
}

func (report *ReportEventReceiver) DisplayReportURL() {
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n\n%s\n\n", report.message))
}
