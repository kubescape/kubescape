package cautils

import (
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// ControlFilters selects only frameworks in which this control was evaluated.
// Missing framework context deliberately retains framework-agnostic semantics.
func ControlFilters(summary *reportsummary.SummaryDetails, controlID string) *helpersv1.Filters {
	var names []string
	if summary != nil {
		for _, framework := range summary.Frameworks {
			if _, ok := framework.Controls[controlID]; ok && framework.GetName() != "" {
				names = append(names, framework.GetName())
			}
		}
	}
	return &helpersv1.Filters{FrameworkNames: names}
}

// ControlStatus returns the selected-framework view without changing evaluation.
// Controls without exceptions retain their cached status, including legacy
// reports with incomplete rules and explicit skipped/passed control outcomes.
func ControlStatus(summary *reportsummary.SummaryDetails, control *resourcesresults.ResourceAssociatedControl) apis.IStatus {
	// Collection/coverage limits are not reconstructed from rule results.
	if control.Status.SubStatus == apis.SubStatusNotEvaluated {
		return control.GetStatus(nil)
	}
	if control.Status.InnerStatus != apis.StatusPassed && control.Status.InnerStatus != apis.StatusFailed && (control.Status.InnerStatus != "" || control.Status.InnerInfo != "") {
		switch control.Status.SubStatus {
		case apis.SubStatusManualReview, apis.SubStatusRequiresReview, apis.SubStatusConfiguration:
		default:
			return control.GetStatus(nil)
		}
	}
	hasExceptions := false
	for i := range control.ResourceAssociatedRules {
		if len(control.ResourceAssociatedRules[i].Exception) > 0 {
			hasExceptions = true
			break
		}
	}
	if !hasExceptions {
		return control.GetStatus(nil)
	}
	return control.GetStatus(ControlFilters(summary, control.ControlID))
}

// RuleStatus evaluates a rule in its containing control's framework context.
func RuleStatus(summary *reportsummary.SummaryDetails, controlID string, rule *resourcesresults.ResourceAssociatedRule) apis.IStatus {
	filters := ControlFilters(summary, controlID)
	view := *rule
	view.Exception = exceptions.FilterExceptionsByFrameworks(rule.Exception, filters.FrameworkNames, controlID, rule.Name)
	return view.GetStatus(filters)
}

// ResourceStatus folds control-specific views rather than applying every
// selected framework to controls that may not belong to that framework.
func ResourceStatus(summary *reportsummary.SummaryDetails, result *resourcesresults.Result) apis.IStatus {
	status, subStatus := apis.StatusUnknown, apis.SubStatusUnknown
	for i := range result.AssociatedControls {
		effective := ControlStatus(summary, &result.AssociatedControls[i])
		status, subStatus = apis.CompareStatusAndSubStatus(status, effective.Status(), subStatus, effective.GetSubStatus())
	}
	return &apis.StatusInfo{InnerStatus: status, SubStatus: subStatus, InnerInfo: apis.SubStatusInfo(subStatus)}
}

// FailedRules returns a shallow control copy containing only rules that still
// fail in the selected frameworks, retaining statusless legacy evidence.
// Evidence consumers can enumerate paths on this copy without changing the
// report's raw rules or statuses. Call ControlStatus before filtering rules.
func FailedRules(summary *reportsummary.SummaryDetails, control resourcesresults.ResourceAssociatedControl) resourcesresults.ResourceAssociatedControl {
	rules := make([]resourcesresults.ResourceAssociatedRule, 0, len(control.ResourceAssociatedRules))
	for i := range control.ResourceAssociatedRules {
		if control.ResourceAssociatedRules[i].Status == "" || RuleStatus(summary, control.ControlID, &control.ResourceAssociatedRules[i]).IsFailed() {
			rules = append(rules, control.ResourceAssociatedRules[i])
		}
	}
	control.ResourceAssociatedRules = rules
	return control
}

// ControlIDsByStatus groups controls by their effective selected-framework
// status, using each control's own framework membership.
func ControlIDsByStatus(summary *reportsummary.SummaryDetails, result *resourcesresults.Result) *helpersv1.AllLists {
	controls := &helpersv1.AllLists{}
	controls.Initialize(len(result.AssociatedControls))
	for i := range result.AssociatedControls {
		control := &result.AssociatedControls[i]
		controls.Append(ControlStatus(summary, control).Status(), control.GetID())
	}
	return controls
}
