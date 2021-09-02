package opapolicy

import (
	"bytes"
	"encoding/json"
)

func (pn *PolicyNotification) ToJSONBytesBuffer() (*bytes.Buffer, error) {
	res, err := json.Marshal(pn)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(res), err
}

func (RuleResponse *RuleResponse) GetSingleResultStatus() string {
	if RuleResponse.Exception != nil {
		if RuleResponse.Exception.IsAlertOnly() {
			return "warning"
		}
		if RuleResponse.Exception.IsDisable() {
			return "ignore"
		}
	}
	return "failed"

}

func (ruleReport *RuleReport) GetRuleStatus() (string, []RuleResponse, []RuleResponse) {
	if len(ruleReport.RuleResponses) == 0 {
		return "success", nil, nil
	}
	exceptions := make([]RuleResponse, 0)
	failed := make([]RuleResponse, 0)

	for _, rule := range ruleReport.RuleResponses {
		if rule.ExceptionName != "" {
			exceptions = append(exceptions, rule)
		} else if rule.Exception != nil {
			exceptions = append(exceptions, rule)
		} else {
			failed = append(failed, rule)
		}
	}

	status := "failed"
	if len(failed) == 0 && len(exceptions) > 0 {
		status = "warning"
	}
	return status, failed, exceptions
}

func (controlReport *ControlReport) GetNumberOfResources() int {
	sum := 0
	for i := range controlReport.RuleReports {
		if controlReport.RuleReports[i].ListInputResources != nil {
			sum += len(controlReport.RuleReports[i].ListInputResources)
		}
	}
	return sum
}

func (controlReport *ControlReport) ListControlsInputKinds() []string {
	listControlsInputKinds := []string{}
	for i := range controlReport.RuleReports {
		listControlsInputKinds = append(listControlsInputKinds, controlReport.RuleReports[i].ListInputKinds...)
	}
	return listControlsInputKinds
}

func (controlReport *ControlReport) Passed() bool {
	for i := range controlReport.RuleReports {
		if len(controlReport.RuleReports[i].RuleResponses) == 0 {
			return true
		}
	}
	return false
}

func (controlReport *ControlReport) Warning() bool {
	if controlReport.Passed() || controlReport.Failed() {
		return false
	}
	for i := range controlReport.RuleReports {
		if status, _, _ := controlReport.RuleReports[i].GetRuleStatus(); status == "warning" {
			return true
		}
	}
	return false
}

func (controlReport *ControlReport) Failed() bool {
	if controlReport.Passed() {
		return false
	}
	for i := range controlReport.RuleReports {
		if status, _, _ := controlReport.RuleReports[i].GetRuleStatus(); status == "failed" {
			return true
		}
	}
	return false
}
