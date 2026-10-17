package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

// The scenario of issue 4214: a hostNetwork Pod fails C-0041 and an exception
// scoped to the NSA framework excepts it.
const (
	hostNetworkControl = "C-0041"
	hostNetworkRule    = "host-network-access"
	otherControl       = "C-0017"
	otherRule          = "immutable-container-filesystem"
)

func hostNetworkPod() workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "hn-pod", "namespace": "default"},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers":  []any{map[string]any{"name": "app", "image": "nginx:1.27"}},
		},
	})
}

func frameworkException(framework string) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "exception-for-" + framework},
		Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
		Resources: []identifiers.PortalDesignator{{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     map[string]string{"kind": "Pod", "name": "hn-pod"},
		}},
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: framework, ControlID: hostNetworkControl}},
	}
}

func failedControl(controlID, ruleName string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		Name:      controlID,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Name: ruleName, Status: apis.StatusFailed},
		},
	}
}

// scanFrameworks maps each framework of the scan to the controls it contains.
type scanFrameworks map[string][]string

func updatedSession(t *testing.T, frameworks scanFrameworks, exceptions ...armotypes.PostureExceptionPolicy) (*OPAProcessor, string) {
	t.Helper()
	pod := hostNetworkPod()
	session := cautils.NewOPASessionObjMock()
	session.AllResources[pod.GetID()] = pod
	session.ResourcesResult[pod.GetID()] = resourcesresults.Result{
		ResourceID: pod.GetID(),
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			failedControl(hostNetworkControl, hostNetworkRule),
			failedControl(otherControl, otherRule),
		},
	}
	session.Exceptions = exceptions
	session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{
		hostNetworkControl: {ControlID: hostNetworkControl},
		otherControl:       {ControlID: otherControl},
	}}

	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		hostNetworkControl: {ControlID: hostNetworkControl},
		otherControl:       {ControlID: otherControl},
	}
	for name, controlIDs := range frameworks {
		controls := reportsummary.ControlSummaries{}
		for _, id := range controlIDs {
			controls[id] = reportsummary.ControlSummary{ControlID: id}
		}
		session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: controls})
	}

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())
	return opap, pod.GetID()
}

func controlOf(t *testing.T, opap *OPAProcessor, resourceID, controlID string) *resourcesresults.ResourceAssociatedControl {
	t.Helper()
	result := opap.ResourcesResult[resourceID]
	for i := range result.AssociatedControls {
		if result.AssociatedControls[i].GetID() == controlID {
			return &result.AssociatedControls[i]
		}
	}
	t.Fatalf("control %s not in the result", controlID)
	return nil
}

func frameworkView(name string) *helpersv1.Filters {
	return &helpersv1.Filters{FrameworkNames: []string{name}}
}

// The library reports the exception only through a framework-filtered view, so
// this is the premise the regression rests on.
func TestFrameworkScopedException_LibraryViewsDiffer(t *testing.T) {
	opap, id := updatedSession(t, scanFrameworks{"NSA": {hostNetworkControl, otherControl}}, frameworkException("NSA"))
	control := controlOf(t, opap, id, hostNetworkControl)

	require.True(t, control.ResourceAssociatedRules[0].GetStatus(nil).IsFailed(), "an unfiltered view ignores a framework-scoped exception")
	rule := control.ResourceAssociatedRules[0].GetStatus(frameworkView("NSA"))
	require.True(t, rule.IsPassed())
	require.Equal(t, apis.SubStatusException, rule.GetSubStatus())
}

func TestUpdateResults_FrameworkScopedExceptionSuppressesFindingInItsFramework(t *testing.T) {
	opap, id := updatedSession(t, scanFrameworks{"NSA": {hostNetworkControl, otherControl}}, frameworkException("NSA"))
	summary := &opap.Report.SummaryDetails
	control := controlOf(t, opap, id, hostNetworkControl)

	// The framework summary and the resource agree.
	nsa := summary.Frameworks[0].Controls[hostNetworkControl]
	require.True(t, nsa.GetStatus().IsPassed())
	require.Equal(t, apis.SubStatusException, nsa.GetSubStatus())

	// Control: the framework-aware view. The unfiltered status is the raw
	// evaluation by design and stays failed.
	require.True(t, control.GetStatus(nil).IsFailed(), "the unfiltered view is the raw evaluation")
	effective := cautils.ControlStatus(summary, control)
	require.True(t, effective.IsPassed())
	require.Equal(t, apis.SubStatusException, effective.GetSubStatus())

	// Rule: raw evaluation is kept, the view is exception-aware.
	rule := &control.ResourceAssociatedRules[0]
	require.Equal(t, apis.StatusFailed, rule.Status, "the raw rule evaluation must not be rewritten")
	require.True(t, cautils.RuleStatus(summary, hostNetworkControl, rule).IsPassed())
	require.Len(t, rule.Exception, 1, "the matched exception stays on the rule for auditing")

	// The unrelated finding stays failed.
	other := controlOf(t, opap, id, otherControl)
	require.True(t, other.GetStatus(nil).IsFailed())
	require.True(t, cautils.ControlStatus(summary, other).IsFailed())

	// The resource still fails, because of the unrelated finding.
	result := opap.ResourcesResult[id]
	require.True(t, cautils.ResourceStatus(summary, &result).IsFailed())
}

func TestUpdateResults_ResourceOnlyFailingTheExceptedControlPasses(t *testing.T) {
	opap, id := updatedSession(t, scanFrameworks{"NSA": {hostNetworkControl}}, frameworkException("NSA"))
	result := opap.ResourcesResult[id]
	result.AssociatedControls = result.AssociatedControls[:1]
	require.True(t, cautils.ResourceStatus(&opap.Report.SummaryDetails, &result).IsPassed())
}

// The exception names NSA, so it must not hide the finding from a framework it
// does not name, even though the control and resource are the same.
func TestUpdateResults_FrameworkScopedExceptionDoesNotLeakToOtherFramework(t *testing.T) {
	t.Run("exception for a framework that is not in the scan", func(t *testing.T) {
		opap, id := updatedSession(t, scanFrameworks{"MITRE": {hostNetworkControl, otherControl}}, frameworkException("NSA"))
		summary := &opap.Report.SummaryDetails
		control := controlOf(t, opap, id, hostNetworkControl)

		require.True(t, control.GetStatus(nil).IsFailed())
		require.True(t, cautils.ControlStatus(summary, control).IsFailed())
		require.True(t, cautils.RuleStatus(summary, hostNetworkControl, &control.ResourceAssociatedRules[0]).IsFailed())
		summarized := summary.Frameworks[0].Controls[hostNetworkControl]
		require.True(t, summarized.GetStatus().IsFailed(), "the summary agrees")
	})

	t.Run("control contained in a covered and an uncovered framework", func(t *testing.T) {
		opap, id := updatedSession(t, scanFrameworks{
			"NSA":   {hostNetworkControl, otherControl},
			"MITRE": {hostNetworkControl, otherControl},
		}, frameworkException("NSA"))
		summary := &opap.Report.SummaryDetails
		control := controlOf(t, opap, id, hostNetworkControl)
		rule := &control.ResourceAssociatedRules[0]

		// Per framework view: passed in NSA, failed in MITRE.
		require.True(t, control.GetStatus(frameworkView("NSA")).IsPassed())
		require.True(t, control.GetStatus(frameworkView("MITRE")).IsFailed())
		require.True(t, rule.GetStatus(frameworkView("NSA")).IsPassed())
		require.True(t, rule.GetStatus(frameworkView("MITRE")).IsFailed())

		// The consumers' combined view stays failed, and so does the record.
		require.True(t, cautils.ControlStatus(summary, control).IsFailed())
		require.True(t, cautils.RuleStatus(summary, hostNetworkControl, rule).IsFailed())

		// Summary per framework agrees with the per-framework views, regardless of order.
		for _, fw := range summary.Frameworks {
			summarized := fw.Controls[hostNetworkControl]
			require.Equal(t, fw.Name == "NSA", summarized.GetStatus().IsPassed(), fw.Name)
			require.Equal(t, fw.Name == "MITRE", summarized.GetStatus().IsFailed(), fw.Name)
		}
	})

	t.Run("control only contained in the covered framework", func(t *testing.T) {
		opap, id := updatedSession(t, scanFrameworks{
			"NSA":   {hostNetworkControl, otherControl},
			"MITRE": {otherControl},
		}, frameworkException("NSA"))
		summary := &opap.Report.SummaryDetails
		control := controlOf(t, opap, id, hostNetworkControl)

		require.True(t, cautils.ControlStatus(summary, control).IsPassed(), "MITRE does not evaluate this control, so it cannot keep it failed")
	})

	t.Run("matching is case-insensitive like the library", func(t *testing.T) {
		opap, id := updatedSession(t, scanFrameworks{"nsa": {hostNetworkControl}}, frameworkException("NSA"))
		require.True(t, cautils.ControlStatus(&opap.Report.SummaryDetails, controlOf(t, opap, id, hostNetworkControl)).IsPassed())
	})
}

func TestUpdateResults_FrameworkAgnosticExceptionStillApplies(t *testing.T) {
	agnostic := frameworkException("")
	agnostic.PosturePolicies = []armotypes.PosturePolicy{{ControlID: hostNetworkControl}}
	opap, id := updatedSession(t, scanFrameworks{"NSA": {hostNetworkControl}, "MITRE": {hostNetworkControl}}, agnostic)

	control := controlOf(t, opap, id, hostNetworkControl)
	require.True(t, cautils.ControlStatus(&opap.Report.SummaryDetails, control).IsPassed())
}

func TestUpdateResults_WithoutExceptionsNothingChanges(t *testing.T) {
	opap, id := updatedSession(t, scanFrameworks{"NSA": {hostNetworkControl, otherControl}})
	summary := &opap.Report.SummaryDetails
	for _, controlID := range []string{hostNetworkControl, otherControl} {
		control := controlOf(t, opap, id, controlID)
		require.Equal(t, apis.StatusInfo{InnerStatus: apis.StatusFailed}, control.Status, "the recorded status is untouched")
		require.Equal(t, apis.StatusFailed, control.GetStatus(nil).Status())
		require.True(t, cautils.ControlStatus(summary, control).IsFailed())
		require.Empty(t, control.ResourceAssociatedRules[0].Exception)
	}
}
