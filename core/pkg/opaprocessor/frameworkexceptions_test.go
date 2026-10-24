package opaprocessor

import (
	"context"
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
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

func TestFrameworkScopedManualExceptions(t *testing.T) {
	tests := []struct {
		name       string
		policies   []armotypes.PosturePolicy
		frameworks []string
		excepted   map[string]bool
		aggregate  bool
	}{
		{name: "none", frameworks: []string{"NSA", "MITRE"}},
		{name: "NSA", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "MITRE", policies: []armotypes.PosturePolicy{{FrameworkName: "MITRE", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"MITRE": true}},
		{name: "global", policies: []armotypes.PosturePolicy{{ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true, "MITRE": true}, aggregate: true},
		{name: "case insensitive", policies: []armotypes.PosturePolicy{{FrameworkName: "nsa", ControlID: "c-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "regex", policies: []armotypes.PosturePolicy{{FrameworkName: "N.*", ControlID: "C-028[6]"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "regex mismatch", policies: []armotypes.PosturePolicy{{FrameworkName: "N.*", ControlID: "C-0286"}}, frameworks: []string{"XNSA", "MITRE"}},
		{name: "tuples", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0287"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true}},
		{name: "both", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0286"}}, frameworks: []string{"NSA", "MITRE"}, excepted: map[string]bool{"NSA": true, "MITRE": true}, aggregate: true},
		{name: "single", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}, frameworks: []string{"NSA"}, excepted: map[string]bool{"NSA": true}, aggregate: true},
		{name: "missing framework scoped", policies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}}},
		{name: "missing framework global", policies: []armotypes.PosturePolicy{{ControlID: "C-0286"}}, aggregate: true},
		{name: "unnamed framework", policies: []armotypes.PosturePolicy{{FrameworkName: ".*", ControlID: "C-0286"}}, frameworks: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				session := cautils.NewOPASessionObjMock()
				session.AuditExceptions = true
				manual := reportsummary.ControlSummary{ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}}
				session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0286": manual}
				for i := range tt.frameworks {
					if reverse {
						i = len(tt.frameworks) - 1 - i
					}
					session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: tt.frameworks[i], Controls: reportsummary.ControlSummaries{"C-0286": manual}})
				}
				if tt.policies != nil {
					session.Exceptions = []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: "manual exception"}, PosturePolicies: tt.policies}}
				}
				before, err := json.Marshal(session.Exceptions)
				require.NoError(t, err)
				opap := &OPAProcessor{OPASessionObj: session}
				opap.updateResults(context.Background())
				after, err := json.Marshal(session.Exceptions)
				require.NoError(t, err)
				assert.JSONEq(t, string(before), string(after), "input policies must remain intact")
				check := func(sd reportsummary.SummaryDetails) {
					assertManualExceptionStatus(t, sd.Controls["C-0286"], tt.aggregate)
					for _, fw := range sd.Frameworks {
						assertManualExceptionStatus(t, fw.Controls["C-0286"], tt.excepted[fw.Name])
					}
				}
				check(session.Report.SummaryDetails)
				data, err := json.Marshal(session.Report.SummaryDetails)
				require.NoError(t, err)
				var restored reportsummary.SummaryDetails
				require.NoError(t, json.Unmarshal(data, &restored))
				check(restored)
				if tt.policies != nil {
					require.Len(t, opap.ExceptionAudit.Items, 1)
					wantCount := 0
					if tt.aggregate || len(tt.excepted) > 0 {
						wantCount = 1
					}
					assert.Equal(t, wantCount, opap.ExceptionAudit.Items[0].MatchCount)
				}
			}
		})
	}
}

func assertManualExceptionStatus(t *testing.T, ctrl reportsummary.ControlSummary, excepted bool) {
	t.Helper()
	status, sub := apis.StatusSkipped, apis.SubStatusManualReview
	if excepted {
		status, sub = apis.StatusPassed, apis.SubStatusException
	}
	assert.Equal(t, status, ctrl.GetStatus().Status())
	assert.Equal(t, sub, ctrl.GetStatus().GetSubStatus())
}

func TestFrameworkScopedManualMembershipAndAudit(t *testing.T) {
	for _, action := range []armotypes.PostureExceptionPolicyActions{"", armotypes.Disable, armotypes.AlertOnly} {
		name := string(action)
		if name == "" {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.AuditExceptions = true
			manual := reportsummary.ControlSummary{ControlID: "C-0286", StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}}
			session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0286": manual}
			session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
				{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0286": manual}},
				{Name: "MITRE", Controls: reportsummary.ControlSummaries{}},
			}
			session.Exceptions = []armotypes.PostureExceptionPolicy{{
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0286"}, {FrameworkName: "MITRE", ControlID: "C-0287"}},
			}}
			if action != "" {
				session.Exceptions[0].Actions = []armotypes.PostureExceptionPolicyActions{action}
			}
			key := exceptionAuditKey(session.Exceptions[0])
			opap := &OPAProcessor{OPASessionObj: session}
			opap.updateResults(context.Background())
			assertManualExceptionStatus(t, session.Report.SummaryDetails.Controls["C-0286"], true)
			require.Len(t, session.ExceptionAudit.Items, 1)
			assert.Equal(t, 1, session.ExceptionAudit.Items[0].MatchCount)
			assert.Equal(t, key, exceptionAuditKey(session.Exceptions[0]), "unnamed exception identity remains intact")
			assert.Len(t, session.ExceptionAudit.Items[0].ControlIDs, 2, "audit retains original tuples, including unmatched controls")
		})
	}
}

func TestFrameworkScopedResourceExceptions(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		frameworks  []string
		want        map[string]apis.ScanningStatus
		aggregate   apis.ScanningStatus
	}{
		{"none", "none", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusFailed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"NSA", "NSA", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"global", "", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusPassed}, apis.StatusPassed},
		{"unselected", "NSA", []string{"MITRE"}, map[string]apis.ScanningStatus{"MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"unrelated framework", "NSA", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"unselected tuples", "NSA", []string{"MITRE"}, map[string]apis.ScanningStatus{"MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"missing framework scoped", "NSA", nil, nil, apis.StatusFailed},
		{"missing framework global", "", nil, nil, apis.StatusPassed},
		{"single", "NSA", []string{"NSA"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed}, apis.StatusPassed},
		{"case insensitive", "nsa", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"regex", "N.*", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
		{"tuples", "NSA", []string{"NSA", "MITRE"}, map[string]apis.ScanningStatus{"NSA": apis.StatusPassed, "MITRE": apis.StatusFailed}, apis.StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				session := cautils.NewOPASessionObjMock()
				resource := workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "test", "namespace": "default"}})
				session.AllResources[resource.GetID()] = resource
				session.ResourcesResult[resource.GetID()] = resourcesresults.Result{ResourceID: resource.GetID(), AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "R1", Status: apis.StatusFailed}}}}}
				session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{"C-0034": {ControlID: "C-0034"}}}
				session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}
				for i := range tc.frameworks {
					if reverse {
						i = len(tc.frameworks) - 1 - i
					}
					controls := reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}
					if tc.name == "unrelated framework" && tc.frameworks[i] == "NSA" {
						// Selecting NSA does not make its exception applicable to a
						// control evaluated only in MITRE.
						controls = reportsummary.ControlSummaries{}
					}
					session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: tc.frameworks[i], Controls: controls})
				}
				if tc.scope != "none" {
					session.Exceptions = []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tc.scope, ControlID: "C-0034", RuleName: "R1"}}}}
				}
				if tc.name == "tuples" || tc.name == "unselected tuples" {
					session.Exceptions[0].PosturePolicies = append(session.Exceptions[0].PosturePolicies, armotypes.PosturePolicy{FrameworkName: "MITRE", ControlID: "C-0034", RuleName: "R2"})
				}
				session.AuditExceptions = true
				recorder := &capturingRecorder{}
				opap := &OPAProcessor{OPASessionObj: session, exceptionEventRecorder: recorder}
				opap.updateResults(context.Background())
				wantMatches := 0
				if tc.name != "none" && tc.name != "unselected" && tc.name != "unrelated framework" && tc.name != "unselected tuples" && tc.name != "missing framework scoped" {
					wantMatches = 1
				}
				assert.Len(t, recorder.events, wantMatches)
				assert.Equal(t, wantMatches, session.ExceptionAudit.Summary.Matched)
				if tc.scope != "none" {
					require.Len(t, session.ExceptionAudit.Items, 1)
					item := session.ExceptionAudit.Items[0]
					assert.Equal(t, wantMatches, item.MatchCount)
					assert.Len(t, item.MatchedResources, wantMatches)
					assert.Equal(t, 1-wantMatches, session.ExceptionAudit.Summary.Unused)
					if wantMatches == 0 {
						assert.Equal(t, exceptionAuditStatusUnused, item.Status)
					} else {
						assert.Equal(t, exceptionAuditStatusMatched, item.Status)
					}
				}
				check := func(sd reportsummary.SummaryDetails) {
					ctrl := sd.Controls["C-0034"]
					assert.Equal(t, tc.aggregate, ctrl.GetStatus().Status())
					assert.Equal(t, tc.aggregate, sd.GetStatus().Status())
					for _, fw := range sd.Frameworks {
						if _, ok := fw.Controls["C-0034"]; !ok {
							continue
						}
						c := fw.Controls["C-0034"]
						assert.Equal(t, tc.want[fw.Name], c.GetStatus().Status(), fw.Name)
						wantSub := apis.SubStatusUnknown
						if tc.want[fw.Name] == apis.StatusPassed {
							wantSub = apis.SubStatusException
						}
						assert.Equal(t, wantSub, c.GetStatus().GetSubStatus(), fw.Name)
					}
				}
				check(session.Report.SummaryDetails)
				data, err := json.Marshal(session.Report.SummaryDetails)
				require.NoError(t, err)
				var restored reportsummary.SummaryDetails
				require.NoError(t, json.Unmarshal(data, &restored))
				check(restored)
				resultData, err := json.Marshal(session.ResourcesResult[resource.GetID()])
				require.NoError(t, err)
				var restoredResult resourcesresults.Result
				require.NoError(t, json.Unmarshal(resultData, &restoredResult))
				assert.Equal(t, tc.aggregate, cautils.ResourceStatus(&restored, &restoredResult).Status())
				assert.Equal(t, apis.StatusFailed, session.ResourcesResult[resource.GetID()].AssociatedControls[0].ResourceAssociatedRules[0].Status, "raw evaluation remains failed")
			}
		})
	}
}
