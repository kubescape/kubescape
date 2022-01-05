package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
	uuid "github.com/satori/go.uuid"
)

const MAX_REPORT_SIZE = 2097152 // 2 MB

type ReportEventReceiver struct {
	httpClient         *http.Client
	clusterName        string
	customerGUID       string
	eventReceiverURL   *url.URL
	token              string
	customerAdminEMail string
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

	if report.customerGUID == "" || report.clusterName == "" {
		return fmt.Errorf("missing accout ID or cluster name. AccountID: '%s', Cluster name: '%s'", report.customerGUID, report.clusterName)
	}
	opaSessionObj.PostureReport.ReportID = uuid.NewV4().String()
	opaSessionObj.PostureReport.CustomerGUID = report.clusterName
	opaSessionObj.PostureReport.ClusterName = report.customerGUID

	if err := report.prepareReport(opaSessionObj.PostureReport, opaSessionObj.AllResources); err != nil {
		return err
	}
	return nil
}

func (report *ReportEventReceiver) SetCustomerGUID(customerGUID string) {
	report.customerGUID = customerGUID
}

func (report *ReportEventReceiver) SetClusterName(clusterName string) {
	report.clusterName = cautils.AdoptClusterName(clusterName) // clean cluster name
}

func (report *ReportEventReceiver) prepareReport(postureReport *reporthandling.PostureReport, allResources map[string]workloadinterface.IMetadata) error {
	report.initEventReceiverURL()
	host := hostToString(report.eventReceiverURL, postureReport.ReportID)

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	// send framework results
	if err := report.sendReport(host, postureReport); err != nil {
		return err
	}

	// send resources
	if err := report.sendResources(host, postureReport, allResources); err != nil {
		return err
	}
	return nil
}

func (report *ReportEventReceiver) sendResources(host string, postureReport *reporthandling.PostureReport, allResources map[string]workloadinterface.IMetadata) error {
	splittedPostureReport := setPaginationReport(postureReport)
	counter := 0

	for _, v := range allResources {
		r, err := json.Marshal(*iMetaToResource(v))
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource '%s', reason: %v", v.GetID(), err)
		}

		if counter+len(r) >= MAX_REPORT_SIZE && len(splittedPostureReport.Resources) > 0 {

			// send report
			if err := report.sendReport(host, splittedPostureReport); err != nil {
				return err
			}

			// delete resources
			splittedPostureReport.Resources = []reporthandling.Resource{}

			// restart counter
			counter = 0
		}

		counter += len(r)
		splittedPostureReport.Resources = append(splittedPostureReport.Resources, *iMetaToResource(v))
	}

	return report.sendReport(host, splittedPostureReport)
}
func (report *ReportEventReceiver) sendReport(host string, postureReport *reporthandling.PostureReport) error {
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

func (report *ReportEventReceiver) DisplayReportURL() {
	message := "You can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more by registering here:"

	u := url.URL{}
	u.Scheme = "https"
	u.Host = getter.GetArmoAPIConnector().GetFrontendURL()

	if report.customerAdminEMail != "" {
		cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n\n%s %s/risk/%s\n(Account: %s)\n\n", message, u.String(), report.clusterName, report.customerGUID))
		return
	}
	u.Path = "account/sign-up"
	q := u.Query()
	q.Add("invitationToken", report.token)
	q.Add("customerGUID", report.customerGUID)

	u.RawQuery = q.Encode()
	cautils.InfoTextDisplay(os.Stderr, fmt.Sprintf("\n\n%s %s\n\n", message, u.String()))
}
