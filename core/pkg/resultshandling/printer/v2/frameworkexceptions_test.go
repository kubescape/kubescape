package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

const (
	testHostNetworkControl = "C-0041"
	testOtherControl       = "C-0017"
)

// A report as opa-utils v0.0.315 records it: the control and its rule keep the
// raw failed status and the framework-scoped exception hangs on the rule.
func sessionWithFrameworkException(t *testing.T, frameworks map[string][]string, withUnrelatedFinding bool) (*cautils.OPASessionObj, string) {
	t.Helper()
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "hn-pod", "namespace": "default"},
		"spec":     map[string]any{"hostNetwork": true},
	})

	excepted := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network-access",
		Status: apis.StatusFailed,
		Paths:  []armotypes.PosturePaths{{ReviewPath: "spec.hostNetwork"}},
		Exception: []armotypes.PostureExceptionPolicy{{
			PortalBase:      armotypes.PortalBase{Name: "nsa-only-hostnetwork"},
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
		}},
	}
	controls := []resourcesresults.ResourceAssociatedControl{{
		ControlID: testHostNetworkControl, Name: "HostNetwork access",
		Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{excepted},
	}}
	if withUnrelatedFinding {
		controls = append(controls, resourcesresults.ResourceAssociatedControl{
			ControlID: testOtherControl, Name: "Immutable container filesystem",
			Status: apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{Name: "immutable-container-filesystem", Status: apis.StatusFailed},
			},
		})
	}

	session := cautils.NewOPASessionObjMock()
	session.AllResources[pod.GetID()] = pod
	session.ResourcesResult[pod.GetID()] = resourcesresults.Result{ResourceID: pod.GetID(), AssociatedControls: controls}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		testHostNetworkControl: {ControlID: testHostNetworkControl},
		testOtherControl:       {ControlID: testOtherControl},
	}
	for name, controlIDs := range frameworks {
		summaries := reportsummary.ControlSummaries{}
		for _, id := range controlIDs {
			summaries[id] = reportsummary.ControlSummary{ControlID: id}
		}
		session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: summaries})
	}
	return session, pod.GetID()
}

// Consumers must agree with the summary they print next to: the finding is gone
// where the exception's framework is the one scanned, and stays where it is not.
func TestResourceViews_FrameworkScopedException(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frameworks map[string][]string
		wantShown  bool
	}{
		{"scanned framework is excepted", map[string][]string{"NSA": {testHostNetworkControl}}, false},
		{"framework without the exception", map[string][]string{"MITRE": {testHostNetworkControl}}, true},
		{"excepted and unexcepted frameworks together", map[string][]string{"NSA": {testHostNetworkControl}, "MITRE": {testHostNetworkControl}}, true},
		{"unexcepted framework does not evaluate the control", map[string][]string{"NSA": {testHostNetworkControl}, "MITRE": {testOtherControl}}, false},
		{"no framework context", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, id := sessionWithFrameworkException(t, tc.frameworks, false)

			// the resource table / pretty output
			require.Equal(t, tc.wantShown, len(failedResourcesInPrintOrder(session)) == 1)
			// the HTML report
			require.Equal(t, tc.wantShown, len(buildResourceTableView(session, false)) == 1)
			// the "Controls: N (Failed: M)" counters
			result := session.ResourcesResult[id]
			counters := cautils.ControlIDsByStatus(&session.Report.SummaryDetails, &result)
			require.Equal(t, 1, counters.Len())
			require.Equal(t, tc.wantShown, counters.Failed() == 1)
			require.Equal(t, !tc.wantShown, counters.Passed() == 1)
		})
	}
}

func TestResourceViews_UnrelatedFindingStaysVisible(t *testing.T) {
	session, id := sessionWithFrameworkException(t, map[string][]string{"NSA": {testHostNetworkControl, testOtherControl}}, true)

	require.Len(t, failedResourcesInPrintOrder(session), 1, "the resource still fails because of the unrelated control")
	view := buildResourceTableView(session, false)
	require.Len(t, view, 1)
	require.Len(t, view[0].ControlsResult, 1)
	require.Equal(t, testOtherControl, view[0].ControlsResult[0].ID)

	result := session.ResourcesResult[id]
	counters := cautils.ControlIDsByStatus(&session.Report.SummaryDetails, &result)
	require.Equal(t, 1, counters.Failed())
	require.Equal(t, 1, counters.Passed())
}

// The JSON/YAML/CSV reports carry the control status the summary reports (as
// v0.0.312 did), and serializing does not alter the scan's own evaluation.
func TestEnrichResult_RecordsFrameworkAwareControlStatus(t *testing.T) {
	session, id := sessionWithFrameworkException(t, map[string][]string{"NSA": {testHostNetworkControl, testOtherControl}}, true)
	summary := &session.Report.SummaryDetails
	result := session.ResourcesResult[id]

	enriched := enrichResultWithSeverity(result, summary, nil)
	byID := map[string]apis.IStatus{}
	for i := range enriched.AssociatedControls {
		byID[enriched.AssociatedControls[i].GetID()] = enriched.AssociatedControls[i].GetStatus(nil)
	}
	require.True(t, byID[testHostNetworkControl].IsPassed())
	require.Equal(t, apis.SubStatusException, byID[testHostNetworkControl].GetSubStatus())
	require.True(t, byID[testOtherControl].IsFailed(), "an unrelated finding is not touched")

	require.Equal(t, apis.StatusFailed, session.ResourcesResult[id].AssociatedControls[0].Status.InnerStatus, "the evaluation held by the scan keeps its raw status")
	require.Equal(t, apis.StatusFailed, result.AssociatedControls[0].ResourceAssociatedRules[0].Status)

	// ... and another framework does not inherit NSA's exception.
	other, otherID := sessionWithFrameworkException(t, map[string][]string{"MITRE": {testHostNetworkControl}}, false)
	otherResult := other.ResourcesResult[otherID]
	enriched = enrichResultWithSeverity(otherResult, &other.Report.SummaryDetails, nil)
	require.True(t, enriched.AssociatedControls[0].GetStatus(nil).IsFailed())
}

func TestEnrichResult_WithoutExceptionsKeepsRecordedStatus(t *testing.T) {
	session, id := sessionWithFrameworkException(t, map[string][]string{"NSA": {testHostNetworkControl}}, false)
	result := session.ResourcesResult[id]
	result.AssociatedControls[0].ResourceAssociatedRules[0].Exception = nil

	enriched := enrichResultWithSeverity(result, &session.Report.SummaryDetails, nil)
	require.Equal(t, result.AssociatedControls[0].Status, enriched.AssociatedControls[0].Status)
}

func TestEnrichResult_NilSummaryDoesNotPanic(t *testing.T) {
	session, id := sessionWithFrameworkException(t, map[string][]string{"NSA": {testHostNetworkControl}}, true)
	result := session.ResourcesResult[id]

	var enriched ResultWithSeverity
	require.NotPanics(t, func() {
		enriched = enrichResultWithSeverity(result, nil, nil)
	})
	require.Len(t, enriched.AssociatedControls, len(result.AssociatedControls))
	for _, ac := range enriched.AssociatedControls {
		require.Equal(t, "Unknown", ac.Severity)
	}
}

func TestEnrichResults_NilSummaryDoesNotPanic(t *testing.T) {
	session, id := sessionWithFrameworkException(t, map[string][]string{"NSA": {testHostNetworkControl}}, true)
	results := []resourcesresults.Result{session.ResourcesResult[id]}

	var enriched []ResultWithSeverity
	require.NotPanics(t, func() {
		enriched = enrichResultsWithSeverity(results, nil, nil)
	})
	require.Len(t, enriched, 1)
	require.Len(t, enriched[0].AssociatedControls, len(results[0].AssociatedControls))
	for _, ac := range enriched[0].AssociatedControls {
		require.Equal(t, "Unknown", ac.Severity)
	}
}
