package printer

import (
	"encoding/json"
	"strings"
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
	exceptedEvidencePath = "spec.hostNetwork"
	failingEvidencePath  = "spec.hostPID"
)

// A pod that trips two rules of one control: host networking, which an NSA
// exception suppresses, and host PID, which nothing suppresses (unless
// failingRuleToo is false, when the control has only the suppressed rule).
func sessionWithPartlyExceptedControl(t *testing.T, failingRuleToo bool) (*cautils.OPASessionObj, string) {
	t.Helper()
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "two-rules", "namespace": "default"},
		"spec":     map[string]any{"hostNetwork": true, "hostPID": true},
	})
	rules := []resourcesresults.ResourceAssociatedRule{{
		Name:   "host-network-access",
		Status: apis.StatusFailed,
		Paths:  []armotypes.PosturePaths{{ResourceID: pod.GetID(), ReviewPath: exceptedEvidencePath}},
		Exception: []armotypes.PostureExceptionPolicy{{
			PortalBase:      armotypes.PortalBase{Name: "nsa-only-hostnetwork"},
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
		}},
	}}
	if failingRuleToo {
		rules = append(rules, resourcesresults.ResourceAssociatedRule{
			Name:   "host-pid-access",
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{{ResourceID: pod.GetID(), ReviewPath: failingEvidencePath}},
		})
	}

	session := cautils.NewOPASessionObjMock()
	session.AllResources[pod.GetID()] = pod
	session.ResourcesResult[pod.GetID()] = resourcesresults.Result{
		ResourceID: pod.GetID(),
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID: testHostNetworkControl, Name: "HostNetwork access",
			Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: rules,
		}},
	}
	controls := reportsummary.ControlSummaries{testHostNetworkControl: {ControlID: testHostNetworkControl, Name: "HostNetwork access"}}
	session.Report.SummaryDetails.Controls = controls
	session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{{Name: "NSA", Controls: controls}}
	return session, pod.GetID()
}

func TestEvidence_ExceptedRuleIsNotDisplayedBesideAFailingRule(t *testing.T) {
	session, id := sessionWithPartlyExceptedControl(t, true)
	summary := &session.Report.SummaryDetails
	result := session.ResourcesResult[id]
	resource := session.AllResources[id]

	// JSON evidence
	enriched := enrichResultWithSeverity(result, summary, resource)
	require.Len(t, enriched.AssociatedControls, 1)
	control := enriched.AssociatedControls[0]
	serialized, err := json.Marshal(control.Evidence)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), exceptedEvidencePath)
	require.Contains(t, string(serialized), failingEvidencePath)

	// the same control is still failed, and its raw rules are all there for audit
	require.True(t, control.GetStatus(nil).IsFailed())
	require.Len(t, control.ResourceAssociatedRules, 2)
	require.Len(t, control.ResourceAssociatedRules[0].Exception, 1)
	require.Equal(t, exceptedEvidencePath, control.ResourceAssociatedRules[0].Paths[0].ReviewPath)

	// HTML remediation
	view := buildResourceTableView(session, false)
	require.Len(t, view, 1)
	require.Len(t, view[0].ControlsResult, 1)
	html := strings.Join(view[0].ControlsResult[0].FailedPaths, "\n")
	require.NotContains(t, html, exceptedEvidencePath)
	require.Contains(t, html, failingEvidencePath)

	// resource table evidence
	rows := generateResourceRows(result.AssociatedControls, summary, resource, true, false, "", nil)
	require.Len(t, rows, 1)
	require.NotContains(t, rows[0][resourceColumnPath], exceptedEvidencePath)
	require.Contains(t, rows[0][resourceColumnPath], failingEvidencePath)

	// nothing above rewrote the scan's own evaluation
	raw := session.ResourcesResult[id].AssociatedControls[0]
	require.Len(t, raw.ResourceAssociatedRules, 2)
	require.Equal(t, apis.StatusFailed, raw.ResourceAssociatedRules[0].Status)
	require.Equal(t, "nsa-only-hostnetwork", raw.ResourceAssociatedRules[0].Exception[0].Name)
}

func TestEvidence_FullyExceptedControlOffersNoActionableEvidence(t *testing.T) {
	session, id := sessionWithPartlyExceptedControl(t, false)
	summary := &session.Report.SummaryDetails
	result := session.ResourcesResult[id]
	resource := session.AllResources[id]

	enriched := enrichResultWithSeverity(result, summary, resource)
	require.Len(t, enriched.AssociatedControls, 1)
	control := enriched.AssociatedControls[0]
	require.Empty(t, control.Evidence)
	require.True(t, control.GetStatus(nil).IsPassed())
	require.Equal(t, apis.SubStatusException, control.GetStatus(nil).GetSubStatus())
	// the suppressed rule and its exception remain in the report for audit
	require.Len(t, control.ResourceAssociatedRules, 1)
	require.Len(t, control.ResourceAssociatedRules[0].Exception, 1)
	require.Equal(t, exceptedEvidencePath, control.ResourceAssociatedRules[0].Paths[0].ReviewPath)

	require.Empty(t, buildResourceTableView(session, false), "the resource no longer fails, so the HTML lists nothing to fix")

	// even asked directly, the table row builders offer nothing for the control
	require.Empty(t, generateResourceRows(result.AssociatedControls, summary, resource, true, false, "", nil))
	displayed := cautils.EvidenceControl(summary, result.AssociatedControls[0])
	require.Empty(t, displayed.ResourceAssociatedRules)
	require.Len(t, result.AssociatedControls[0].ResourceAssociatedRules, 1)
}
