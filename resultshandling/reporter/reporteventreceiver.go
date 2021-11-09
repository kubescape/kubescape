package reporter

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

type IReport interface {
	ActionSendReport(opaSessionObj *cautils.OPASessionObj) error
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
}

type ReportEventReceiver struct {
	httpClient   *http.Client
	clusterName  string
	customerGUID string
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

	if err := report.send(opaSessionObj.PostureReport); err != nil {
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

func (report *ReportEventReceiver) send(postureReport *reporthandling.PostureReport) error {

	reqBody, err := json.Marshal(*postureReport)
	if err != nil {
		return fmt.Errorf("in 'Send' failed to json.Marshal, reason: %v", err)
	}
	host := hostToString(report.initEventReceiverURL(), postureReport.ReportID)

	msg, err := getter.HttpPost(report.httpClient, host, reqBody)
	if err != nil {
		return fmt.Errorf("%s, %v:%s", host, err, msg)
	}
	return err
}
