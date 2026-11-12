package opaprocessor

import (
	"context"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// failEveryPodRego fails every Pod it sees. The good control in these tests
// uses it to prove the rest of the scan still produces verdicts.
const failEveryPodRego = `package armo_builtins

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	msga := {
		"alertMessage": "pod found",
		"packagename": "armo_builtins",
		"alertScore": 1,
		"fixPaths": [],
		"reviewPaths": [],
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

// conflictInNamespaceARego hits eval_conflict_error at runtime, but only when
// it sees a Pod in namespace ns-a: conflict_fn then has two values for the
// same input. Pods anywhere else evaluate cleanly.
const conflictInNamespaceARego = `package armo_builtins

conflict_fn(x) := 1 {
	true
}

conflict_fn(x) := 2 {
	x.metadata.namespace == "ns-a"
}

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	conflict_fn(pod) == 1
	msga := {
		"alertMessage": "pod found",
		"packagename": "armo_builtins",
		"alertScore": 1,
		"fixPaths": [],
		"reviewPaths": [],
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

const goodControlID = "C-GOOD"

var podMatch = []reporthandling.RuleMatchObjects{{
	APIGroups:   []string{""},
	APIVersions: []string{"v1"},
	Resources:   []string{"Pod"},
}}

func ruleErrorTestPod(name, namespace string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "app", "image": "nginx",
		}}},
	})
}

func ruleErrorTestControl(controlID, ruleName string, rule reporthandling.PolicyRule) reporthandling.Control {
	rule.Name = ruleName
	rule.Match = podMatch
	control := reporthandling.Control{ControlID: controlID, BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = controlID + " control"
	return control
}

// ruleErrorTestSession returns a session holding a good control that fails
// every Pod and the given broken control. InfoMap is set the way the real
// constructor sets it, since the mock leaves it nil.
func ruleErrorTestSession(broken reporthandling.Control) *cautils.OPASessionObj {
	good := ruleErrorTestControl(goodControlID, "fail-every-pod", reporthandling.PolicyRule{Rule: failEveryPodRego, RuleLanguage: reporthandling.RegoLanguage})
	framework := reporthandling.Framework{Controls: []reporthandling.Control{good, broken}}
	framework.Name = "rule-error-framework"

	session := cautils.NewOPASessionObjMock()
	session.InfoMap = map[string]apis.StatusInfo{}
	session.K8SResources = cautils.K8SResources{}
	session.Policies = []reporthandling.Framework{framework}
	return session
}

func liveBinding(t *testing.T, controlID, name string) metav1unstructured.Unstructured {
	t.Helper()
	policyName, err := cel.PolicyNameForControl(controlID)
	require.NoError(t, err)
	return metav1unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"policyName": policyName},
	}}
}

// runEager scans pods with ProcessRulesListener.
func runEager(session *cautils.OPASessionObj, pods ...workloadinterface.IMetadata) error {
	for _, pod := range pods {
		session.K8SResources["/v1/pods"] = append(session.K8SResources["/v1/pods"], pod.GetID())
		session.AllResources[pod.GetID()] = pod
	}
	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	return processor.ProcessRulesListener(context.Background(), nil)
}

// runStreaming scans pods with ProcessWithStreaming: an empty resident batch,
// then one batch per namespace, in the order given.
func runStreaming(session *cautils.OPASessionObj, namespaces []string, pods ...workloadinterface.IMetadata) error {
	batchChan := make(chan *cautils.ResourceBatch, 1+len(namespaces))
	batchChan <- cautils.NewResourceBatch(cautils.ClusterScope)
	for _, namespace := range namespaces {
		batch := cautils.NewResourceBatch(namespace)
		for _, pod := range pods {
			if pod.GetNamespace() != namespace {
				continue
			}
			batch.K8SResources["/v1/pods"] = append(batch.K8SResources["/v1/pods"], pod.GetID())
			batch.AllResources[pod.GetID()] = pod
		}
		batchChan <- batch
	}
	close(batchChan)
	errChan := make(chan error)
	close(errChan)

	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	return processor.ProcessWithStreaming(context.Background(), batchChan, errChan, nil, len(namespaces))
}

// requireNotEvaluated checks the broken control is reported as not evaluated,
// with a reason that names the cause, on the control and in the coverage.
func requireNotEvaluated(t *testing.T, session *cautils.OPASessionObj, controlID, reasonContains string) {
	t.Helper()
	summary, ok := session.Report.SummaryDetails.Controls[controlID]
	require.True(t, ok, "control %s missing from the summary", controlID)
	status := summary.GetStatus()
	assert.Equal(t, apis.StatusSkipped, status.Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, status.GetSubStatus())
	assert.Contains(t, status.Info(), reasonContains)

	var listed bool
	for _, notEvaluated := range session.ScanCoverage.NotEvaluatedControls {
		if notEvaluated.ControlID == controlID {
			listed = true
			assert.Contains(t, notEvaluated.Reason, reasonContains)
		}
	}
	assert.True(t, listed, "control %s not listed in ScanCoverage.NotEvaluatedControls", controlID)
	assert.Equal(t, session.ScanCoverage.TotalControls-1, session.ScanCoverage.EvaluatedControls)
}

func requireGoodControlFailed(t *testing.T, session *cautils.OPASessionObj, failed int) {
	t.Helper()
	good := session.Report.SummaryDetails.Controls[goodControlID]
	assert.Equal(t, apis.StatusFailed, good.GetStatus().Status())
	assert.Equal(t, failed, good.NumberOfResources().Failed())
}

// A rule that cannot be evaluated must cost only its own control. Before,
// any of these errors made the whole scan fail with no report.
func TestRuleLevelErrorsSkipTheControl(t *testing.T) {
	cases := []struct {
		name           string
		broken         reporthandling.Control
		bindings       func(t *testing.T) []metav1unstructured.Unstructured
		reasonContains string
	}{
		{
			name:           "CEL control missing from the embedded bundle",
			broken:         ruleErrorTestControl("C-9999", "cel-missing-policy", reporthandling.PolicyRule{RuleLanguage: reporthandling.CELLanguage}),
			reasonContains: `no ValidatingAdmissionPolicy for control "C-9999" in embedded bundle`,
		},
		{
			name:   "CEL policy matched by two live bindings",
			broken: ruleErrorTestControl("C-0004", "cel-two-bindings", reporthandling.PolicyRule{RuleLanguage: reporthandling.CELLanguage}),
			bindings: func(t *testing.T) []metav1unstructured.Unstructured {
				return []metav1unstructured.Unstructured{liveBinding(t, "C-0004", "binding-a"), liveBinding(t, "C-0004", "binding-b")}
			},
			reasonContains: "is matched by 2 live bindings",
		},
		{
			name:           "Rego rule that does not compile",
			broken:         ruleErrorTestControl("C-BROKEN", "broken-rego", reporthandling.PolicyRule{Rule: "package armo_builtins\nthis is not valid rego {{{", RuleLanguage: reporthandling.RegoLanguage}),
			reasonContains: "rego_parse_error",
		},
		{
			name:           "Rego rule that errors at runtime",
			broken:         ruleErrorTestControl("C-CONFLICT", "conflicting-rego", reporthandling.PolicyRule{Rule: conflictInNamespaceARego, RuleLanguage: reporthandling.RegoLanguage}),
			reasonContains: "eval_conflict_error",
		},
		{
			name:           "unsupported rule language",
			broken:         ruleErrorTestControl("C-LANG", "unknown-language", reporthandling.PolicyRule{RuleLanguage: reporthandling.RuleLanguages("Python")}),
			reasonContains: "language 'Python' not supported",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("eager", func(t *testing.T) {
				session := ruleErrorTestSession(tc.broken)
				if tc.bindings != nil {
					session.VAPBindings = tc.bindings(t)
				}

				err := runEager(session, ruleErrorTestPod("pod", "ns-a"))

				require.NoError(t, err)
				requireGoodControlFailed(t, session, 1)
				requireNotEvaluated(t, session, tc.broken.ControlID, tc.reasonContains)
			})
			t.Run("streaming", func(t *testing.T) {
				session := ruleErrorTestSession(tc.broken)
				if tc.bindings != nil {
					session.VAPBindings = tc.bindings(t)
				}

				err := runStreaming(session, []string{"ns-a"}, ruleErrorTestPod("pod", "ns-a"))

				require.NoError(t, err)
				requireGoodControlFailed(t, session, 1)
				requireNotEvaluated(t, session, tc.broken.ControlID, tc.reasonContains)
			})
		})
	}
}

// Streaming used to return at the first scope that errored, so later
// namespace batches were never evaluated and the summary was never built.
func TestRuleErrorInOneNamespaceDoesNotStopLaterBatches(t *testing.T) {
	broken := ruleErrorTestControl("C-CONFLICT", "conflicting-rego", reporthandling.PolicyRule{Rule: conflictInNamespaceARego, RuleLanguage: reporthandling.RegoLanguage})
	session := ruleErrorTestSession(broken)
	podA := ruleErrorTestPod("pod-a", "ns-a")
	podB := ruleErrorTestPod("pod-b", "ns-b")

	err := runStreaming(session, []string{"ns-a", "ns-b"}, podA, podB)

	require.NoError(t, err)
	resultB, ok := session.ResourcesResult[podB.GetID()]
	require.True(t, ok, "the ns-b batch after the failing ns-a batch was never evaluated")
	var goodVerdict bool
	for _, control := range resultB.AssociatedControls {
		if control.ControlID == goodControlID {
			goodVerdict = true
			assert.Equal(t, apis.StatusFailed, control.GetStatus(nil).Status())
		}
	}
	assert.True(t, goodVerdict, "pod-b has no verdict for %s", goodControlID)
	requireGoodControlFailed(t, session, 2)
	requireNotEvaluated(t, session, broken.ControlID, "eval_conflict_error")
}

// Errors that mean the scan itself cannot run still fail it.
func TestScanLevelErrorsStillFailTheScan(t *testing.T) {
	newSession := func() *cautils.OPASessionObj {
		return ruleErrorTestSession(ruleErrorTestControl("C-OTHER", "fail-every-pod-again", reporthandling.PolicyRule{Rule: failEveryPodRego, RuleLanguage: reporthandling.RegoLanguage}))
	}
	collectionErr := errors.New("list pods: forbidden")

	cases := []struct {
		name    string
		run     func(t *testing.T) error
		checkIs error
	}{
		{
			name: "eager scan whose context is cancelled",
			run: func(t *testing.T) error {
				session := newSession()
				pod := ruleErrorTestPod("pod", "ns-a")
				session.K8SResources["/v1/pods"] = []string{pod.GetID()}
				session.AllResources[pod.GetID()] = pod
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
				return processor.ProcessRulesListener(ctx, nil)
			},
			checkIs: context.Canceled,
		},
		{
			name: "control filter that leaves nothing to scan",
			run: func(t *testing.T) error {
				session := newSession()
				session.IncludeControls = "C-DOES-NOT-EXIST"
				processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
				return processor.ProcessRulesListener(context.Background(), nil)
			},
		},
		{
			name: "streaming resource collection failure",
			run: func(t *testing.T) error {
				batchChan := make(chan *cautils.ResourceBatch, 1)
				batchChan <- cautils.NewResourceBatch(cautils.ClusterScope)
				errChan := make(chan error, 1)
				errChan <- collectionErr
				processor := NewOPAProcessor(newSession(), resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
				return processor.ProcessWithStreaming(context.Background(), batchChan, errChan, nil, 1)
			},
			checkIs: collectionErr,
		},
		{
			name: "streaming with no resident batch",
			run: func(t *testing.T) error {
				batchChan := make(chan *cautils.ResourceBatch)
				close(batchChan)
				errChan := make(chan error)
				close(errChan)
				processor := NewOPAProcessor(newSession(), resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
				return processor.ProcessWithStreaming(context.Background(), batchChan, errChan, nil, 0)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			require.Error(t, err)
			if tc.checkIs != nil {
				assert.ErrorIs(t, err, tc.checkIs)
			}
		})
	}
}

// In verify mode a whole-cluster control that errors used to end the loop,
// so the whole-cluster controls after it were never evaluated.
func TestVerifyWholeCluster_RuleErrorSkipsAndContinues(t *testing.T) {
	wholeCluster := func(controlID, ruleName, rego string) reporthandling.Control {
		control := ruleErrorTestControl(controlID, ruleName, reporthandling.PolicyRule{Rule: rego, RuleLanguage: reporthandling.RegoLanguage})
		control.PortalBase = armotypes.PortalBase{
			Name:       control.Name,
			Attributes: map[string]any{ControlAttributeRequiresWholeClusterInput: true},
		}
		return control
	}
	// Sorted control order puts C-A-BROKEN before C-B-GOOD.
	broken := wholeCluster("C-A-BROKEN", "broken-rego", "package armo_builtins\nthis is not valid rego {{{")
	good := wholeCluster("C-B-GOOD", "fail-every-pod", failEveryPodRego)
	policies := &cautils.Policies{Controls: map[string]reporthandling.Control{
		broken.ControlID: broken,
		good.ControlID:   good,
	}}

	pod := ruleErrorTestPod("pod", "ns-a")
	session := cautils.NewOPASessionObjMock()
	session.K8SResources = cautils.K8SResources{"/v1/pods": {pod.GetID()}}
	session.AllResources[pod.GetID()] = pod
	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	processor.AllPolicies = policies
	processor.SetWholeClusterPolicy(cautils.WholeClusterPolicyVerify)

	err := processor.Process(context.Background(), policies, nil)

	require.NoError(t, err)
	assert.Contains(t, processor.ErroredControls[broken.ControlID], "rego_parse_error")
	var goodVerdict bool
	for _, control := range session.ResourcesResult[pod.GetID()].AssociatedControls {
		if control.ControlID == good.ControlID {
			goodVerdict = true
		}
	}
	assert.True(t, goodVerdict, "%s after the broken control was never evaluated", good.ControlID)
}

func TestMarkControlErrored_KeepsFirstReasonAndTimeoutWins(t *testing.T) {
	processor := NewOPAProcessor(cautils.NewOPASessionObjMock(), resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	first := &reporthandling.Control{ControlID: "C-FIRST"}
	timedOut := &reporthandling.Control{ControlID: "C-TIMEOUT"}

	processor.markControlErrored(first, errors.New("first error"))
	processor.markControlErrored(first, errors.New("second error"))
	processor.markControlTimedOut(timedOut, 0)
	processor.markControlErrored(timedOut, errors.New("late error"))

	assert.Equal(t, "control evaluation failed: first error", processor.ErroredControls["C-FIRST"])
	assert.NotContains(t, processor.ErroredControls, "C-TIMEOUT")
	assert.True(t, processor.controlNotEvaluated("C-FIRST"))
	assert.True(t, processor.controlNotEvaluated("C-TIMEOUT"))
	assert.False(t, processor.controlNotEvaluated("C-OTHER"))

	reasons := processor.notEvaluatedReasons()
	assert.Equal(t, "control evaluation failed: first error", reasons["C-FIRST"])
	assert.Equal(t, processor.TimedOutControls["C-TIMEOUT"], reasons["C-TIMEOUT"])
}

// A CEL rule's evaluation error must not be labelled as a Rego one.
func TestRuleEvalLanguage(t *testing.T) {
	assert.Equal(t, "cel", ruleEvalLanguage(&reporthandling.PolicyRule{RuleLanguage: reporthandling.CELLanguage}))
	assert.Equal(t, "rego", ruleEvalLanguage(&reporthandling.PolicyRule{RuleLanguage: reporthandling.RegoLanguage}))
	assert.Equal(t, "rego", ruleEvalLanguage(&reporthandling.PolicyRule{RuleLanguage: reporthandling.RegoLanguage2}))
}
