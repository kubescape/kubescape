package reporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

const MAX_REPORT_SIZE = 2097152 // 2 MB

type IReport interface {
	ActionSendReport(opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
}

type ReportEventReceiver struct {
	httpClient       *http.Client
	clusterName      string
	customerGUID     string
	eventReceiverURL *url.URL
}

func NewReportEventReceiver(customerGUID, clusterName string) *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient:   &http.Client{},
		clusterName:  clusterName,
		customerGUID: customerGUID,
	}
}

func (report *ReportEventReceiver) ActionSendReport(opaSessionObj *cautils.OPASessionObj) error {
	// Remove data before reporting
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "namespace", "labels"}
	opaSessionObj.PostureReport.RemoveData(keepFields, keepMetadataFields)

	if err := report.prepareReport(opaSessionObj.PostureReport, opaSessionObj.AllResources); err != nil {
		return err
	}
	return nil
}

func (report *ReportEventReceiver) SetCustomerGUID(customerGUID string) {
	report.customerGUID = customerGUID
}

func (report *ReportEventReceiver) SetClusterName(clusterName string) {
	report.clusterName = clusterName
}

func (report *ReportEventReceiver) prepareReport(postureReport *reporthandling.PostureReport, allResources map[string]workloadinterface.IMetadata) error {
	report.initEventReceiverURL()
	host := hostToString(report.eventReceiverURL, postureReport.ReportID)

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

// func (report *ReportEventReceiver) send(postureReport *reporthandling.PostureReport) error {
// 	report.initEventReceiverURL()
// 	reqBody, err := json.Marshal(*postureReport)
// 	if err != nil {
// 		return fmt.Errorf("in 'Send' failed to json.Marshal, reason: %v", err)
// 	}
// 	host := hostToString(report.eventReceiverURL, postureReport.ReportID)

// 	msg, err := getter.HttpPost(report.httpClient, host, nil, reqBody)
// 	if err != nil {
// 		return fmt.Errorf("%s, %v:%s", host, err, msg)
// 	}
// 	return err
// }
