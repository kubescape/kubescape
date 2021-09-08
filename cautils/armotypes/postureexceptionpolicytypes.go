package armotypes

type PostureExceptionPolicyActions string

const AlertOnly PostureExceptionPolicyActions = "alertOnly"
const Disable PostureExceptionPolicyActions = "disable"

type PostureExceptionPolicy struct {
	PortalBase      `json:",inline"`
	PolicyType      string                          `json:"policyType"`
	CreationTime    string                          `json:"creationTime"`
	Actions         []PostureExceptionPolicyActions `json:"actions"`
	Resources       []PortalDesignator              `json:"resources"`
	PosturePolicies []PosturePolicy                 `json:"posturePolicies"`
}

type PosturePolicy struct {
	FrameworkName string `json:"frameworkName"`
	ControlName   string `json:"controlName"`
	RuleName      string `json:"ruleName"`
}

func (exceptionPolicy *PostureExceptionPolicy) IsAlertOnly() bool {
	if exceptionPolicy.IsDisable() {
		return false
	}

	for i := range exceptionPolicy.Actions {
		if exceptionPolicy.Actions[i] == AlertOnly {
			return true
		}
	}
	return false
}
func (exceptionPolicy *PostureExceptionPolicy) IsDisable() bool {
	for i := range exceptionPolicy.Actions {
		if exceptionPolicy.Actions[i] == Disable {
			return true
		}
	}
	return false
}
