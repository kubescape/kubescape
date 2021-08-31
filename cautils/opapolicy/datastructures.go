package opapolicy

import (
	"path/filepath"
	"time"

	armotypes "kubescape/cautils/armotypes"
)

type AlertScore float32
type RuleLanguages string

const (
	RegoLanguage  RuleLanguages = "Rego"
	RegoLanguage2 RuleLanguages = "rego"
)

// RegoResponse the expected response of single run of rego policy
type RuleResponse struct {
	AlertMessage string     `json:"alertMessage"`
	PackageName  string     `json:"packagename"`
	AlertScore   AlertScore `json:"alertScore"`
	// AlertObject   AlertObject `json:"alertObject"`
	AlertObject   AlertObject `json:"alertObject"` // TODO - replace interface to AlertObject
	Context       []string    `json:"context"`     // TODO - Remove
	Rulename      string      `json:"rulename"`    // TODO - Remove
	ExceptionName string      `json:"exceptionName"`
}

type AlertObject struct {
	K8SApiObjects   []map[string]interface{} `json:"k8sApiObjects,omitempty"`
	ExternalObjects map[string]interface{}   `json:"externalObjects,omitempty"`
}

type FrameworkReport struct {
	Name           string          `json:"name"`
	ControlReports []ControlReport `json:"controlReports"`
}
type ControlReport struct {
	Name        string       `json:"name"`
	RuleReports []RuleReport `json:"ruleReports"`
	Remediation string       `json:"remediation"`
	Description string       `json:"description"`
}
type RuleReport struct {
	Name               string                   `json:"name"`
	Remediation        string                   `json:"remediation"`
	RuleStatus         RuleStatus               `json:"ruleStatus"`
	RuleResponses      []RuleResponse           `json:"ruleResponses"`
	ListInputResources []map[string]interface{} `json:"-"`
	ListInputKinds     []string                 `json:"-"`
}
type RuleStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// PostureReport
type PostureReport struct {
	CustomerGUID         string            `json:"customerGUID"`
	ClusterName          string            `json:"clusterName"`
	ReportID             string            `json:"reportID"`
	JobID                string            `json:"jobID"`
	ReportGenerationTime time.Time         `json:"generationTime"`
	FrameworkReports     []FrameworkReport `json:"frameworks"`
}

// RuleMatchObjects defines which objects this rule applied on
type RuleMatchObjects struct {
	APIGroups   []string `json:"apiGroups"`   // apps
	APIVersions []string `json:"apiVersions"` // v1/ v1beta1 / *
	Resources   []string `json:"resources"`   // dep.., pods,
}

// RuleMatchObjects defines which objects this rule applied on
type RuleDependency struct {
	PackageName string `json:"packageName"` // package name
}

// PolicyRule represents single rule, the fundamental executable block of policy
type PolicyRule struct {
	armotypes.PortalBase `json:",inline"`
	CreationTime         string             `json:"creationTime"`
	Rule                 string             `json:"rule"` // multiline string!
	RuleLanguage         RuleLanguages      `json:"ruleLanguage"`
	Match                []RuleMatchObjects `json:"match"`
	RuleDependencies     []RuleDependency   `json:"ruleDependencies"`
	Description          string             `json:"description"`
	Remediation          string             `json:"remediation"`
	RuleQuery            string             `json:"ruleQuery"` // default "armo_builtins" - DEPRECATED
}

// Control represents a collection of rules which are combined together to single purpose
type Control struct {
	armotypes.PortalBase `json:",inline"`
	CreationTime         string       `json:"creationTime"`
	Description          string       `json:"description"`
	Remediation          string       `json:"remediation"`
	Rules                []PolicyRule `json:"rules"`
	// for new list of  rules in POST/UPADTE requests
	RulesIDs *[]string `json:"rulesIDs,omitempty"`
}

type UpdatedControl struct {
	Control `json:",inline"`
	Rules   []interface{} `json:"rules"`
}

// Framework represents a collection of controls which are combined together to expose comprehensive behavior
type Framework struct {
	armotypes.PortalBase `json:",inline"`
	CreationTime         string    `json:"creationTime"`
	Description          string    `json:"description"`
	Controls             []Control `json:"controls"`
	// for new list of  controls in POST/UPADTE requests
	ControlsIDs *[]string `json:"controlsIDs,omitempty"`
}

type UpdatedFramework struct {
	Framework `json:",inline"`
	Controls  []interface{} `json:"controls"`
}

type NotificationPolicyType string
type NotificationPolicyKind string

// Supported NotificationTypes
const (
	TypeValidateRules   NotificationPolicyType = "validateRules"
	TypeExecPostureScan NotificationPolicyType = "execPostureScan"
	TypeUpdateRules     NotificationPolicyType = "updateRules"
)

// Supported NotificationKinds
const (
	KindFramework NotificationPolicyKind = "Framework"
	KindControl   NotificationPolicyKind = "Control"
	KindRule      NotificationPolicyKind = "Rule"
)

type PolicyNotification struct {
	NotificationType NotificationPolicyType     `json:"notificationType"`
	Rules            []PolicyIdentifier         `json:"rules"`
	ReportID         string                     `json:"reportID"`
	JobID            string                     `json:"jobID"`
	Designators      armotypes.PortalDesignator `json:"designators"`
}

type PolicyIdentifier struct {
	Kind NotificationPolicyKind `json:"kind"`
	Name string                 `json:"name"`
}

type ScanInfo struct {
	PolicyIdentifier   PolicyIdentifier
	Format             string
	Output             string
	ExcludedNamespaces string
	InputPatterns      []string
	Silent             bool
}

func (scanInfo *ScanInfo) Init() {
	// scanInfo.setSilentMode()
	scanInfo.setOutputFile()

}

func (scanInfo *ScanInfo) setSilentMode() {
	if scanInfo.Format == "json" || scanInfo.Format == "junit" {
		scanInfo.Silent = true
	}
	if scanInfo.Output != "" {
		scanInfo.Silent = true
	}
}

func (scanInfo *ScanInfo) setOutputFile() {
	if scanInfo.Output == "" {
		return
	}
	if scanInfo.Format == "json" {
		if filepath.Ext(scanInfo.Output) != "json" {
			scanInfo.Output += ".json"
		}
	}
	if scanInfo.Format == "junit" {
		if filepath.Ext(scanInfo.Output) != "xml" {
			scanInfo.Output += ".xml"
		}
	}
}
