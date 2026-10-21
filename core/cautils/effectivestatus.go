package cautils

import (
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// Since opa-utils v0.0.313, GetStatus(nil) returns the evaluation as if no
// framework were selected, so an exception scoped to a framework (a
// posturePolicy with a frameworkName) is ignored there and only applies to a
// view filtered by that framework. The summary is computed per framework, so a
// consumer that reads a resource, control or rule with GetStatus(nil) disagrees
// with the summary it prints next to. The helpers below give every consumer the
// same view the summary uses: a control is evaluated in the frameworks of the
// scan that contain it.

// ControlFilters selects the frameworks of the scan that contain controlID. With
// no summary, or a control that no framework lists, it selects none, which is the
// framework-agnostic view GetStatus(nil) returns.
func ControlFilters(summary *reportsummary.SummaryDetails, controlID string) *helpersv1.Filters {
	filters := &helpersv1.Filters{}
	if summary == nil {
		return filters
	}
	for i := range summary.Frameworks {
		framework := &summary.Frameworks[i]
		if _, ok := framework.Controls[controlID]; ok && framework.GetName() != "" {
			filters.FrameworkNames = append(filters.FrameworkNames, framework.GetName())
		}
	}
	return filters
}

// ControlStatus is the status of one resource's control in the frameworks that
// contain it. A framework not covered by an exception keeps the finding failed,
// so the result never hides a finding that only another framework excepted.
//
// Only a control with a matched exception is re-evaluated; any other keeps its
// recorded status, so results without exceptions are unchanged.
func ControlStatus(summary *reportsummary.SummaryDetails, control *resourcesresults.ResourceAssociatedControl) apis.IStatus {
	if !hasException(control) {
		return control.GetStatus(nil)
	}
	return control.GetStatus(ControlFilters(summary, control.GetID()))
}

// RuleStatus is the status of one rule of the control controlID, in the
// frameworks that contain that control.
func RuleStatus(summary *reportsummary.SummaryDetails, controlID string, rule *resourcesresults.ResourceAssociatedRule) apis.IStatus {
	if len(rule.Exception) == 0 {
		return rule.GetStatus(nil)
	}
	return rule.GetStatus(ControlFilters(summary, controlID))
}

// FrameworkRuleStatus is the status of one rule evaluated in a single framework,
// for output that belongs to that framework alone (a section of the legacy v1
// report). An exception scoped to another framework does not apply to it. With
// no framework name it falls back to RuleStatus.
func FrameworkRuleStatus(summary *reportsummary.SummaryDetails, frameworkName, controlID string, rule *resourcesresults.ResourceAssociatedRule) apis.IStatus {
	if frameworkName == "" {
		return RuleStatus(summary, controlID, rule)
	}
	if len(rule.Exception) == 0 {
		return rule.GetStatus(nil)
	}
	return rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{frameworkName}})
}

// ResourceStatus folds the framework-aware status of each control of the
// resource, the way Result.GetStatus folds the recorded ones.
func ResourceStatus(summary *reportsummary.SummaryDetails, result *resourcesresults.Result) apis.IStatus {
	status, subStatus := apis.StatusUnknown, apis.SubStatusUnknown
	for i := range result.AssociatedControls {
		controlStatus := ControlStatus(summary, &result.AssociatedControls[i])
		status, subStatus = apis.CompareStatusAndSubStatus(status, controlStatus.Status(), subStatus, controlStatus.GetSubStatus())
	}
	return &apis.StatusInfo{InnerStatus: status, SubStatus: subStatus, InnerInfo: apis.SubStatusInfo(subStatus)}
}

// FailedRules returns a copy of the control holding only the rules that still
// fail in the control's frameworks, for consumers that enumerate the evidence of
// a failing control. The report's own rules are not modified.
func FailedRules(summary *reportsummary.SummaryDetails, control resourcesresults.ResourceAssociatedControl) resourcesresults.ResourceAssociatedControl {
	rules := make([]resourcesresults.ResourceAssociatedRule, 0, len(control.ResourceAssociatedRules))
	for i := range control.ResourceAssociatedRules {
		if RuleStatus(summary, control.GetID(), &control.ResourceAssociatedRules[i]).IsFailed() {
			rules = append(rules, control.ResourceAssociatedRules[i])
		}
	}
	control.ResourceAssociatedRules = rules
	return control
}

// EvidenceControl returns the control as its evidence should be displayed: a
// control with a matched exception keeps only the rules that still fail, so the
// paths of an excepted rule are not offered as something to fix. Any other
// control is returned as is. The report's own rules are not modified.
func EvidenceControl(summary *reportsummary.SummaryDetails, control resourcesresults.ResourceAssociatedControl) resourcesresults.ResourceAssociatedControl {
	if !hasException(&control) {
		return control
	}
	return FailedRules(summary, control)
}

// ControlIDsByStatus lists the controls of the resource by their framework-aware
// status, the way Result.ListControlsIDs lists them by recorded status.
func ControlIDsByStatus(summary *reportsummary.SummaryDetails, result *resourcesresults.Result) *helpersv1.AllLists {
	controls := &helpersv1.AllLists{}
	controls.Initialize(len(result.AssociatedControls))
	for i := range result.AssociatedControls {
		control := &result.AssociatedControls[i]
		controls.Append(ControlStatus(summary, control).Status(), control.GetID())
	}
	return controls
}

// SettleControlStatus records the framework-aware status on a control that has
// a matched exception, so the status a report carries agrees with the summary.
// It is meant for a copy made for serialization: the evaluation held by the scan
// keeps its raw status, and the rules keep theirs and their exceptions either way.
func SettleControlStatus(summary *reportsummary.SummaryDetails, control *resourcesresults.ResourceAssociatedControl) {
	if !hasException(control) {
		return
	}
	status := ControlStatus(summary, control)
	control.Status = apis.StatusInfo{InnerStatus: status.Status(), SubStatus: status.GetSubStatus(), InnerInfo: status.Info()}
}

func hasException(control *resourcesresults.ResourceAssociatedControl) bool {
	for i := range control.ResourceAssociatedRules {
		if len(control.ResourceAssociatedRules[i].Exception) > 0 {
			return true
		}
	}
	return false
}
