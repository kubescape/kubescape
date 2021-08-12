package auditconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/elastic/go-elasticsearch/v7/esutil"
	"go.uber.org/zap"
)

func (audit *AuditReport) getIndexName() string {
	return "v1-audit-" + audit.CustomerGUID
}

func (audit *AuditReport) doReportAuditReport() error {
	indexName := audit.getIndexName()
	esRequest := esapi.IndexRequest{
		Index: indexName,
		Body:  esutil.NewJSONReader(*audit),
	}
	err := validateResponse(esRequest.Do(context.Background(), elasticClient))
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") {
			if err = validateResponse(elasticClient.Indices.Create(indexName, elasticClient.API.Indices.Create.WithBody(strings.NewReader(indexMapping)))); err == nil {
				esRequest := esapi.IndexRequest{
					Index: indexName,
					Body:  esutil.NewJSONReader(*audit),
				}
				err = validateResponse(esRequest.Do(context.Background(), elasticClient))
			}
		}
		return err
	}
	return err
}

func validateResponse(res *esapi.Response, err error) error {
	if err != nil {
		return fmt.Errorf("In validateRespons. Primary error. Error: '%v', ", err)
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	elErr := make(map[string]interface{})
	if err := dec.Decode(&elErr); err != nil {
		return fmt.Errorf("In validateResponse failed to decode error body: %v", err)
	}
	if res.IsError() {
		return fmt.Errorf("In validateResponse error returned (%s): %v, ", res.Status(), elErr)
	}
	zap.L().Info("In validateResponse", zap.Any("result", elErr))
	return nil
}

// AuditReportAction stores the audit report in elastic
func AuditReportAction(action *AuditReport) {
	action.TimeStamp = time.Now()
	if elasticClient != nil {
		go func() {
			if err := action.doReportAuditReport(); err != nil {
				zap.L().Error("In AuditReportAction, failed to doReportAuditReport",
					zap.Any("report", action), zap.Error(err))
			}
		}()
	}
}
