package opapolicy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/rego"
)

func (pn *PolicyNotification) ToJSONBytesBuffer() (*bytes.Buffer, error) {
	res, err := json.Marshal(pn)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(res), err
}

func (ruleReport *RuleReport) GetRuleStatus() (string, []RuleResponse, []RuleResponse) {
	if len(ruleReport.RuleResponses) == 0 {
		return "success", nil, nil
	}
	exceptions := make([]RuleResponse, 0)
	failed := make([]RuleResponse, 0)

	for _, rule := range ruleReport.RuleResponses {
		if rule.ExceptionName != "" {
			failed = append(failed, rule)
		} else {
			exceptions = append(exceptions, rule)
		}
	}

	status := "failed"
	if len(failed) == 0 && len(exceptions) > 0 {
		status = "warning"
	}
	return status, failed, exceptions
}
func ParseRegoResult(regoResult *rego.ResultSet) ([]RuleResponse, error) {
	var errs error
	ruleResponses := []RuleResponse{}
	for _, result := range *regoResult {
		for desicionIdx := range result.Expressions {
			if resMap, ok := result.Expressions[desicionIdx].Value.(map[string]interface{}); ok {
				for objName := range resMap {
					jsonBytes, err := json.Marshal(resMap[objName])
					if err != nil {
						err = fmt.Errorf("in parseRegoResult, json.Marshal failed. name: %s, obj: %v, reason: %s", objName, resMap[objName], err)
						glog.Error(err)
						errs = fmt.Errorf("%s\n%s", errs, err)
						continue
					}
					desObj := make([]RuleResponse, 0)
					if err := json.Unmarshal(jsonBytes, &desObj); err != nil {
						err = fmt.Errorf("in parseRegoResult, json.Unmarshal failed. name: %s, obj: %v, reason: %s", objName, resMap[objName], err)
						glog.Error(err)
						errs = fmt.Errorf("%s\n%s", errs, err)
						continue
					}
					ruleResponses = append(ruleResponses, desObj...)
				}
			}
		}
	}
	return ruleResponses, errs
}

func (controlReport *ControlReport) GetNumberOfResources() int {
	sum := 0
	for i := range controlReport.RuleReports {
		if controlReport.RuleReports[i].ListInputResources == nil {
			continue
		}
		sum += len(controlReport.RuleReports[i].ListInputResources)
	}
	return sum
}

func (controlReport *ControlReport) Passed() bool {
	for i := range controlReport.RuleReports {
		if len(controlReport.RuleReports[i].RuleResponses) > 0 {
			return false
		}
	}
	return true
}

func (controlReport *ControlReport) Failed() bool {
	return !controlReport.Passed()
}
