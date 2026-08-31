package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helpers to build minimal pods
func podWithLabels(name, appLabel string, hostNetwork bool) workloadinterface.IMetadata {
	m := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
			"labels":    map[string]any{"app": appLabel},
		},
		"spec": map[string]any{
			"hostNetwork": hostNetwork,
			"containers":  []any{map[string]any{"name": "c", "image": "nginx"}},
		},
	}
	return workloadinterface.NewWorkloadObj(m)
}

func newTestProcessor(pods []workloadinterface.IMetadata) (*OPAProcessor, *cautils.OPASessionObj) {
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.AllResources = map[string]workloadinterface.IMetadata{}
	opaSessionObj.K8SResources = cautils.K8SResources{}
	opaSessionObj.ResourceToControlsMap = map[string][]string{"/v1/Pod": {"C-TEST"}}
	opaSessionObj.Report = &reporthandlingv2.PostureReport{}
	opaSessionObj.Report.SummaryDetails.Controls = map[string]reportsummary.ControlSummary{}
	opaSessionObj.InfoMap = map[string]apis.StatusInfo{}
	opaSessionObj.Report.ClusterCloudProvider = ""
	// populate
	var ids []string
	for _, p := range pods {
		id := p.GetID()
		opaSessionObj.AllResources[id] = p
		ids = append(ids, id)
	}
	opaSessionObj.K8SResources["/v1/Pod"] = ids
	return NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil), opaSessionObj
}

// TestResourceEnumeratorHonored is the regression test for
// processorhandler.go:1140 — ensure enumeratedData is evaluated, not inputRawResources.
// Without the fix 113 rule instances evaluate against un-narrowed input.
func TestResourceEnumeratorHonored(t *testing.T) {
	tests := []struct {
		name          string
		enumerator    string
		mainRule      string
		pods          []workloadinterface.IMetadata
		expectFailed  []string // pod names expected to be failed
		expectPassed  []string
		expectAbsent  []string // not in ResourcesResult at all (filtered away)
		expectSkipped []string
	}{
		{
			name: "enumerator filters to app=keep — only keep is evaluated",
			enumerator: `package armo_builtins
deny[msg]{ obj:=input[_]; obj.metadata.labels.app=="keep"; msg:={"alertObject":{"k8sApiObjects":[obj]}}}`,
			mainRule: `package armo_builtins
import rego.v1
deny contains msga if { obj:=input[_]; obj.spec.hostNetwork==true; msga:={"alertMessage":"hostNetwork","alertObject":{"k8sApiObjects":[obj]}} }`,
			pods: []workloadinterface.IMetadata{
				podWithLabels("keep-pod", "keep", true),
				podWithLabels("drop-pod", "drop", true),
			},
			expectFailed: []string{"keep-pod"},
			expectAbsent: []string{"drop-pod"},
		},
		{
			name:       "empty enumerator — all pods evaluated",
			enumerator: "",
			mainRule: `package armo_builtins
import rego.v1
deny contains msga if { obj:=input[_]; obj.spec.hostNetwork==true; msga:={"alertMessage":"x","alertObject":{"k8sApiObjects":[obj]}} }`,
			pods: []workloadinterface.IMetadata{
				podWithLabels("keep-pod", "keep", true),
				podWithLabels("drop-pod", "drop", true),
			},
			expectFailed: []string{"keep-pod", "drop-pod"},
		},
		{
			name: "enumerator selects none — no evaluation, no results",
			enumerator: `package armo_builtins
deny[msg]{ obj:=input[_]; obj.metadata.labels.app=="nonexistent"; msg:={"alertObject":{"k8sApiObjects":[obj]}}}`,
			mainRule: `package armo_builtins
import rego.v1
deny contains msga if { obj:=input[_]; obj.spec.hostNetwork==true; msga:={"alertMessage":"x","alertObject":{"k8sApiObjects":[obj]}} }`,
			pods: []workloadinterface.IMetadata{
				podWithLabels("keep-pod", "keep", true),
				podWithLabels("drop-pod", "drop", true),
			},
			expectAbsent: []string{"keep-pod", "drop-pod"},
		},
		{
			name: "enumerator filters then main rule passes — pass reported only for enumerated",
			enumerator: `package armo_builtins
deny[msg]{ obj:=input[_]; obj.metadata.labels.app=="keep"; msg:={"alertObject":{"k8sApiObjects":[obj]}}}`,
			mainRule: `package armo_builtins
import rego.v1
deny contains msga if { obj:=input[_]; obj.spec.hostNetwork==true; obj.metadata.name=="impossible"; msga:={"alertMessage":"x","alertObject":{"k8sApiObjects":[obj]}} }`,
			pods: []workloadinterface.IMetadata{
				podWithLabels("keep-pod", "keep", false),
				podWithLabels("drop-pod", "drop", false),
			},
			expectPassed: []string{"keep-pod"},
			expectAbsent: []string{"drop-pod"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := &reporthandling.PolicyRule{
				PortalBase:         armotypes.PortalBase{Name: "test-rule"},
				Rule:               tc.mainRule,
				ResourceEnumerator: tc.enumerator,
				Match:              []reporthandling.RuleMatchObjects{{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}}},
				RuleLanguage:       reporthandling.RegoLanguage,
			}
			control := &reporthandling.Control{ControlID: "C-TEST", Rules: []reporthandling.PolicyRule{*rule}}
			policies := &cautils.Policies{Controls: map[string]reporthandling.Control{"C-TEST": *control}}
			// session setup per case
			opap, sess := newTestProcessor(tc.pods)
			sess.Policies = []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "fw"}, Controls: []reporthandling.Control{*control}}}
			opap.AllPolicies = policies
			ConvertFrameworksToSummaryDetails(&sess.Report.SummaryDetails, sess.Policies, policies)

			err := opap.Process(context.Background(), policies, nil)
			require.NoError(t, err, "Process should not error for valid enumerator")

			for _, name := range tc.expectFailed {
				found := false
				for _, r := range sess.ResourcesResult {
					for _, ac := range r.AssociatedControls {
						for _, rr := range ac.ResourceAssociatedRules {
							if rr.Name == "test-rule" && rr.Status == apis.StatusFailed {
								// need to locate by name in AllResources
								for _, p := range tc.pods {
									if p.GetName() == name && r.ResourceID == p.GetID() {
										found = true
									}
								}
							}
						}
					}
				}
				assert.True(t, found, "expected %s to be failed", name)
			}
			for _, name := range tc.expectAbsent {
				for _, p := range tc.pods {
					if p.GetName() == name {
						_, ok := sess.ResourcesResult[p.GetID()]
						assert.False(t, ok, "expected %s to be absent (filtered by enumerator), but found in ResourcesResult", name)
					}
				}
			}
			for _, name := range tc.expectPassed {
				found := false
				for _, r := range sess.ResourcesResult {
					for _, ac := range r.AssociatedControls {
						for _, rr := range ac.ResourceAssociatedRules {
							if rr.Name == "test-rule" && rr.Status == apis.StatusPassed {
								for _, p := range tc.pods {
									if p.GetName() == name && r.ResourceID == p.GetID() {
										found = true
									}
								}
							}
						}
					}
				}
				assert.True(t, found, "expected %s to be passed", name)
			}
		})
	}
}

func TestEnumerateData_UsesEnumeratedNotRaw(t *testing.T) {
	// Direct unit test for the bug: processRuleOnScope must not evaluate inputRawResources after enumeration.
	// We use EvaluateRule (correct reference) vs Process (fixed path) and assert they agree.
	podKeep := podWithLabels("keep-pod", "keep", true)
	podDrop := podWithLabels("drop-pod", "drop", true)
	enumerator := `package armo_builtins
deny[msg]{ obj:=input[_]; obj.metadata.labels.app=="keep"; msg:={"alertObject":{"k8sApiObjects":[obj]}}}`
	mainRule := `package armo_builtins
import rego.v1
deny contains msga if { obj:=input[_]; obj.kind=="Pod"; obj.spec.hostNetwork==true; msga:={"alertMessage":"x","alertObject":{"k8sApiObjects":[obj]}} }`
	rule := &reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{Name: "test-rule"}, Rule: mainRule, ResourceEnumerator: enumerator,
		Match:        []reporthandling.RuleMatchObjects{{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}}},
		RuleLanguage: reporthandling.RegoLanguage,
	}
	// Correct path via EvaluateRule
	sess := cautils.NewOPASessionObjMock()
	opapRef := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	refRes, err := opapRef.EvaluateRule(context.Background(), rule, []workloadinterface.IMetadata{podKeep, podDrop}, "C-TEST")
	require.NoError(t, err)
	require.Len(t, refRes, 1, "enumerated path should only fail keep-pod")
	assert.Equal(t, "keep-pod", refRes[0].GetFailedResources()[0]["metadata"].(map[string]any)["name"])

	// Production path via Process
	rule2 := *rule
	control := &reporthandling.Control{ControlID: "C-TEST", Rules: []reporthandling.PolicyRule{rule2}}
	policies := &cautils.Policies{Controls: map[string]reporthandling.Control{"C-TEST": *control}}
	opap, sess2 := newTestProcessor([]workloadinterface.IMetadata{podKeep, podDrop})
	sess2.Policies = []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "fw"}, Controls: []reporthandling.Control{*control}}}
	opap.AllPolicies = policies
	ConvertFrameworksToSummaryDetails(&sess2.Report.SummaryDetails, sess2.Policies, policies)
	require.NoError(t, opap.Process(context.Background(), policies, nil))
	// drop-pod must be absent — if bug present, it would be failed too
	_, hasDrop := sess2.ResourcesResult[podDrop.GetID()]
	assert.False(t, hasDrop, "drop-pod must be filtered by enumerator; buggy code would report it as failed")
	_, hasKeep := sess2.ResourcesResult[podKeep.GetID()]
	assert.True(t, hasKeep, "keep-pod must be present")
}
