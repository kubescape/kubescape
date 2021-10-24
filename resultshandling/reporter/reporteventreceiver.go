package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

type IReport interface {
	ActionSendReport(opaSessionObj *cautils.OPASessionObj)
	SetCustomerGUID(customerGUID string)
	SetClusterName(clusterName string)
}

type ReportEventReceiver struct {
	httpClient   http.Client
	host         url.URL
	clusterName  string
	customerGUID string
}

func NewReportEventReceiver() *ReportEventReceiver {
	return &ReportEventReceiver{
		httpClient: http.Client{},
		// host:       *hostURL,
	}
}

func (report *ReportEventReceiver) ActionSendReport(opaSessionObj *cautils.OPASessionObj) {
	// Remove data before reporting
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "namespace", "labels"}
	opaSessionObj.PostureReport.RemoveData(keepFields, keepMetadataFields)

	if err := report.send(opaSessionObj.PostureReport); err != nil {
		fmt.Println(err)
	}
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

	req, err := http.NewRequest("POST", host, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("in 'Send', http.NewRequest failed, host: %s, reason: %v", host, err)
	}
	res, err := report.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("httpClient.Do failed: %v", err)
	}
	msg, err := httpRespToString(res)
	if err != nil {
		return fmt.Errorf("%s, %v:%s", host, err, msg)
	}
	return err
}
