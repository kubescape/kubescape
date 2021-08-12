package auditconnector

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestAuditReportBasic(t *testing.T) {
	report := AuditReport{
		Source:       AuditSourceTest,
		Details:      "here is some test detail",
		Subject:      "the go compiler",
		Action:       "ran in test mode",
		User:         "ben",
		CustomerGUID: "35d5509a-e81a-492b-a4c6-55264de33e0b",
	}
	err := report.doReportAuditReport()
	if err != nil {
		t.Errorf("error reporting %s", err)
		return
	}

	res, err := elasticClient.Search(elasticClient.Search.WithIndex(report.getIndexName()))
	if err != nil {
		t.Errorf("error retrieving results %s", err)
		return
	}
	defer res.Body.Close()
	if res.IsError() {
		t.Errorf("error retrieving results at ES level %s", res.Status())
		return
	}
	if b, err := ioutil.ReadAll(res.Body); err == nil {
		fmt.Print(string(b))
	}
}

func TestAuditReportGoRutined(t *testing.T) {
	AuditReportAction(&AuditReport{
		Source:       AuditSourceTest,
		Details:      "here is some test detail",
		Subject:      "the go compiler",
		Action:       "ran in test mode",
		User:         "ben",
		CustomerGUID: "35d5509a-e81a-492b-a4c6-55264de33e0b",
	})
}
