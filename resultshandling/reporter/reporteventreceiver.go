package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/armosec/armoapi-go/opapolicy"
	"github.com/armosec/kubescape/cautils"
)

type ReportEventReceiver struct {
	httpClient http.Client
	host       url.URL
}

func NewReportEventReceiver() *ReportEventReceiver {
	hostURL := initEventReceiverURL()
	return &ReportEventReceiver{
		httpClient: http.Client{},
		host:       *hostURL,
	}
}

func (report *ReportEventReceiver) ActionSendReportListenner(opaSessionObj *cautils.OPASessionObj) {
	if cautils.CustomerGUID == "" {
		return
	}
	//Add score

	// Remove data before reporting
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "namespace", "labels"}
	opaSessionObj.PostureReport.RemoveData(keepFields, keepMetadataFields)

	if err := report.Send(opaSessionObj.PostureReport); err != nil {
		fmt.Println(err)
	}
}
func (report *ReportEventReceiver) Send(postureReport *opapolicy.PostureReport) error {

	reqBody, err := json.Marshal(*postureReport)
	if err != nil {
		return fmt.Errorf("in 'Send' failed to json.Marshal, reason: %v", err)
	}
	host := hostToString(&report.host, postureReport.ReportID)

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
