package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

// Verbatim from the shipped C-0054 internal-networking rule (NSA and MITRE).
// The enumerator emits Namespace objects only; the main rule needs the
// NetworkPolicy objects in the same input to decide whether a namespace is
// covered.
const c0054Enumerator = `package armo_builtins

deny[msga] {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}
`

const c0054MainRule = `package armo_builtins

deny[msga] {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]
	policy_names := [policy.metadata.namespace | policy = input[_]; policy.kind == "NetworkPolicy"]
	not list_contains(policy_names, namespace.metadata.name)

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [namespace]
		}
	}
}

list_contains(list, element) {
  some i
  list[i] == element
}
`

// Models the shipped C-0042 rule-can-ssh-to-pod-v1 shape: the enumerator
// reports through externalObjects with an empty k8sApiObjects list, and the
// main rule joins a Pod against a Service in the same namespace.
const c0042Enumerator = `package armo_builtins

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == pod.metadata.namespace

	wlvector = {"name": pod.metadata.name,
				"namespace": pod.metadata.namespace,
				"kind": pod.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("pod %v exposed by service", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["metadata.labels"],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
	}
}
`

const c0042MainRule = `package armo_builtins

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	service := input[_]
	service.kind == "Service"
	service.metadata.namespace == pod.metadata.namespace
	service.spec.ports[_].port == 22

	msga := {
		"alertMessage": sprintf("pod %v is exposed by an SSH service", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}
`

func enumeratorRule(name, mainRule, enumerator string, match []reporthandling.RuleMatchObjects) *reporthandling.PolicyRule {
	rule := &reporthandling.PolicyRule{
		Rule:               mainRule,
		ResourceEnumerator: enumerator,
		RuleLanguage:       reporthandling.RegoLanguage,
		Match:              match,
	}
	rule.Name = name
	return rule
}

// TestEnumeratorPreservesCrossKindJoinInput_FalsePositive drives the real
// shipped C-0054 rego against a namespace that IS covered by a NetworkPolicy.
// The control must not fail it. It fails only when the NetworkPolicy objects
// the main rule joins against are missing from the evaluation input, which is
// what happens when the enumerator's output replaces that input.
func TestEnumeratorPreservesCrossKindJoinInput_FalsePositive(t *testing.T) {
	namespace := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": "prod"},
	})
	netpol := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": "default-deny", "namespace": "prod"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/namespaces":                       {namespace.GetID()},
		"networking.k8s.io/v1/networkpolicies": {netpol.GetID()},
	}
	sess.AllResources[namespace.GetID()] = namespace
	sess.AllResources[netpol.GetID()] = netpol

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	rule := enumeratorRule("internal-networking", c0054MainRule, c0054Enumerator, []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Namespace"}},
		{APIGroups: []string{"networking.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"NetworkPolicy"}},
	})

	got, err := opap.processRule(context.Background(), rule, nil, evaluationScope{}, &reporthandling.Control{})
	require.NoError(t, err)

	result, ok := got[namespace.GetID()]
	require.True(t, ok, "the namespace must appear in the results")
	t.Logf("namespace prod (covered by a NetworkPolicy) -> status=%q", result.GetStatus(nil).Status())

	require.NotEqual(t, apis.StatusFailed, result.GetStatus(nil).Status(),
		"namespace prod is covered by a NetworkPolicy; C-0054 must not fail it")
}

// TestEnumeratorPreservesCrossKindJoinInput_FalseNegative covers the opposite
// direction on the C-0042 shape: an enumerator that reports through
// externalObjects contributes no real Kubernetes objects, so replacing the
// evaluation input with its output leaves the main rule nothing to evaluate
// and the control reports clean on a genuinely exposed pod.
func TestEnumeratorPreservesCrossKindJoinInput_FalseNegative(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "ssh-pod", "namespace": "prod", "labels": map[string]any{"app": "ssh"}},
	})
	service := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "ssh-svc", "namespace": "prod"},
		"spec": map[string]any{
			"selector": map[string]any{"app": "ssh"},
			"ports":    []any{map[string]any{"port": 22}},
		},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/pods":     {pod.GetID()},
		"/v1/services": {service.GetID()},
	}
	sess.AllResources[pod.GetID()] = pod
	sess.AllResources[service.GetID()] = service

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	rule := enumeratorRule("rule-can-ssh-to-pod-v1", c0042MainRule, c0042Enumerator, []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Service"}},
	})

	got, err := opap.processRule(context.Background(), rule, nil, evaluationScope{}, &reporthandling.Control{})
	require.NoError(t, err)

	result, ok := got[pod.GetID()]
	require.True(t, ok, "the pod must appear in the results")
	t.Logf("pod ssh-pod (exposed on port 22) -> status=%q", result.GetStatus(nil).Status())

	require.Equal(t, apis.StatusFailed, result.GetStatus(nil).Status(),
		"pod ssh-pod is exposed by a service on port 22; the control must fail it")
}

// TestEnumeratorExternalObjectsRealC0042 drives the verbatim shipped C-0042
// rule-can-ssh-to-pod-v1 rego (MITRE.json), where both the enumerator and the
// main rule report exclusively through AlertObject.ExternalObjects. It
// guards the refinement that scopes reporting only to K8sApiObjects-derived
// IDs: a RegoResponseVectorObject's GetID is a composite of its own fields
// and never equals the underlying resource's ID, so scoping by it would
// silently drop every real failure this rule (and C-0053) reports.
func TestEnumeratorExternalObjectsRealC0042(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "ssh-pod", "namespace": "prod", "labels": map[string]any{"app": "ssh"}},
	})
	service := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "ssh-svc", "namespace": "prod"},
		"spec": map[string]any{
			"selector": map[string]any{"app": "ssh"},
			"ports":    []any{map[string]any{"port": 22}},
		},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/pods":     {pod.GetID()},
		"/v1/services": {service.GetID()},
	}
	sess.AllResources[pod.GetID()] = pod
	sess.AllResources[service.GetID()] = service

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	rule := enumeratorRule("rule-can-ssh-to-pod-v1", c0042RealMainRule, c0042RealEnumerator, []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Service"}},
	})

	got, err := opap.processRule(context.Background(), rule, nil, evaluationScope{}, &reporthandling.Control{})
	require.NoError(t, err)

	// This rule reports failures through AlertObject.ExternalObjects, so the
	// result is keyed by the reported vector's own composite ID, not
	// pod.GetID() (see RegoResponseVectorObject.GetID) - the same as it was
	// before this fix. What matters here is that a real failure was found and
	// reported at all.
	require.Len(t, got, 1, "the exposed pod must be reported exactly once")
	for _, result := range got {
		t.Logf("real C-0042 rego -> status=%q", result.GetStatus(nil).Status())
		require.Equal(t, apis.StatusFailed, result.GetStatus(nil).Status())
	}
}

// c0042RealEnumerator and c0042RealMainRule are verbatim from
// core/cautils/getter/testdata/MITRE.json, control C-0042, rule
// rule-can-ssh-to-pod-v1.
const c0042RealEnumerator = `package armo_builtins

# input: pod
# apiversion: v1
# does:	returns the external facing services of that pod

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	podns := pod.metadata.namespace
	podname := pod.metadata.name
	labels := pod.metadata.labels
	filtered_labels := json.remove(labels, ["pod-template-hash"])
    path := "metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == podns
	service.spec.selector == filtered_labels


	wlvector = {"name": pod.metadata.name,
				"namespace": pod.metadata.namespace,
				"kind": pod.kind,
				"relatedObjects": service}
	msga := {
		"alertMessage": sprintf("pod %v/%v exposed by SSH services: %v", [podns, podname, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
    }
}

deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	labels := wl.spec.template.metadata.labels
    path := "spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels


	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
     }
}

deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
    path := "spec.jobTemplate.spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels


	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
     }
}
`

const c0042RealMainRule = `package armo_builtins

# input: pod
# apiversion: v1
# does:	returns the external facing services of that pod

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	podns := pod.metadata.namespace
	podname := pod.metadata.name
	labels := pod.metadata.labels
	filtered_labels := json.remove(labels, ["pod-template-hash"])
    path := "metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == podns
	service.spec.selector == filtered_labels
    
	hasSSHPorts(service)

	wlvector = {"name": pod.metadata.name,
				"namespace": pod.metadata.namespace,
				"kind": pod.kind,
				"relatedObjects": service}
	msga := {
		"alertMessage": sprintf("pod %v/%v exposed by SSH services: %v", [podns, podname, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
    }
}

deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	labels := wl.spec.template.metadata.labels
    path := "spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels

	hasSSHPorts(service)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
     }
}

deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	labels := wl.spec.jobTemplate.spec.template.metadata.labels
    path := "spec.jobTemplate.spec.template.metadata.labels"
	service := 	input[_]
	service.kind == "Service"
	service.metadata.namespace == wl.metadata.namespace
	service.spec.selector == labels

	hasSSHPorts(service)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": service}

	msga := {
		"alertMessage": sprintf("%v: %v is exposed by SSH services: %v", [wl.kind, wl.metadata.name, service]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [],
			"externalObjects": wlvector
		}
     }
}

hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.port == 22
}


hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.port == 2222
}

hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.targetPort == 22
}


hasSSHPorts(service) {
	port := service.spec.ports[_]
	port.targetPort == 2222
}
`

// TestNonEnumeratorRuleWithExternalObjectFailureIsReported guards the
// maintainer-flagged regression: a rule with no ResourceEnumerator at all
// that reports its failure through a synthesized AlertObject.ExternalObjects
// (its own identity, not any literal input resource's), the shape
// audit-policy-content (CIS 3.2.2) uses. enumeratedIDs must never restrict
// reporting for such a rule - it only applies to rules that declare a
// ResourceEnumerator.
func TestNonEnumeratorRuleWithExternalObjectFailureIsReported(t *testing.T) {
	node := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata":   map[string]any{"name": "control-plane"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{"/v1/nodes": {node.GetID()}}
	sess.AllResources[node.GetID()] = node

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	rule := &reporthandling.PolicyRule{
		Rule: `package armo_builtins
deny[msga] {
	node := input[_]
	node.kind == "Node"
	vector := {"name": "audit-policy", "namespace": "", "kind": "AuditPolicy", "relatedObjects": node}
	msga := {
		"alertMessage": "audit policy content is invalid",
		"packagename": "armo_builtins",
		"alertScore": 5,
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": vector
		}
	}
}
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Node"}},
		},
	}
	rule.Name = "audit-policy-content"

	got, err := opap.processRule(context.Background(), rule, nil, evaluationScope{}, &reporthandling.Control{})
	require.NoError(t, err)

	// The rule matches Node, so the real Node also appears in the results -
	// passed, since the deny block never names the Node itself as failed.
	// What matters here is that the synthesized ExternalObjects failure is
	// not filtered out.
	var sawFailure bool
	for id, result := range got {
		t.Logf("id=%q status=%q", id, result.GetStatus(nil).Status())
		if result.GetStatus(nil).Status() == apis.StatusFailed {
			sawFailure = true
		}
	}
	require.True(t, sawFailure, "the synthesized ExternalObjects failure must be reported")
}

// TestEnumeratorMixedKubernetesAndVectorFailuresBothReported covers
// CodeRabbit's finding: an enumerator that resolves to real K8sApiObjects for
// one resource and a RegoResponseVectorObject for another (mixed output) must
// not let the K8sApiObjects-derived scope swallow the vector failure. The
// enumerator selects both a Pod (real object, enters enumeratedIDs) and
// reports a Service exposure through ExternalObjects (a vector, whose ID by
// construction is never in enumeratedIDs) - both must still be reportable.
func TestEnumeratorMixedKubernetesAndVectorFailuresBothReported(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "insecure-pod", "namespace": "prod"},
		"spec":       map[string]any{"hostNetwork": true},
	})
	service := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "exposed-svc", "namespace": "prod"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/pods":     {pod.GetID()},
		"/v1/services": {service.GetID()},
	}
	sess.AllResources[pod.GetID()] = pod
	sess.AllResources[service.GetID()] = service

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	rule := enumeratorRule(
		"mixed-enumerator",
		`package armo_builtins
deny[msga] {
	obj := input[_]
	obj.kind == "Pod"
	obj.spec.hostNetwork == true
	msga := {"alertMessage": "hostNetwork pod", "packagename": "armo_builtins", "alertScore": 5, "failedPaths": [], "alertObject": {"k8sApiObjects": [obj]}}
}
deny[msga] {
	obj := input[_]
	obj.kind == "Service"
	vector := {"name": obj.metadata.name, "namespace": obj.metadata.namespace, "kind": obj.kind, "relatedObjects": obj}
	msga := {"alertMessage": "exposed service", "packagename": "armo_builtins", "alertScore": 5, "failedPaths": [], "alertObject": {"k8sApiObjects": [], "externalObjects": vector}}
}
`,
		`package armo_builtins
deny[msga] {
	obj := input[_]
	obj.kind == "Pod"
	obj.spec.hostNetwork == true
	msga := {"alertMessage": "hostNetwork pod", "packagename": "armo_builtins", "alertScore": 5, "failedPaths": [], "alertObject": {"k8sApiObjects": [obj]}}
}
deny[msga] {
	obj := input[_]
	obj.kind == "Service"
	vector := {"name": obj.metadata.name, "namespace": obj.metadata.namespace, "kind": obj.kind, "relatedObjects": obj}
	msga := {"alertMessage": "exposed service", "packagename": "armo_builtins", "alertScore": 5, "failedPaths": [], "alertObject": {"k8sApiObjects": [], "externalObjects": vector}}
}
`,
		[]reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Service"}},
		},
	)

	got, err := opap.processRule(context.Background(), rule, nil, evaluationScope{}, &reporthandling.Control{})
	require.NoError(t, err)

	podResult, ok := got[pod.GetID()]
	require.True(t, ok, "the real Pod failure must be reported")
	require.Equal(t, apis.StatusFailed, podResult.GetStatus(nil).Status())

	var sawVectorFailure bool
	for id, result := range got {
		if id == pod.GetID() {
			continue
		}
		t.Logf("vector-reported entry id=%q status=%q", id, result.GetStatus(nil).Status())
		if result.GetStatus(nil).Status() == apis.StatusFailed {
			sawVectorFailure = true
		}
	}
	require.True(t, sawVectorFailure, "the vector-reported Service exposure must also be reported")
}
