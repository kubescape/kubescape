package vapreconcile

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

const rulesControl = "C-0001"

// resourceRule is one binding resource rule in its unstructured form.
func resourceRule(group, version, resource string, extra map[string]any) any {
	rule := map[string]any{
		"apiGroups":   []any{group},
		"apiVersions": []any{version},
		"operations":  []any{"CREATE", "UPDATE"},
		"resources":   []any{resource},
	}
	for k, v := range extra {
		rule[k] = v
	}
	return rule
}

// bindingWithMatchResources is a binding for policy "p" carrying the given
// spec.matchResources (omitted when nil).
func bindingWithMatchResources(name string, matchResources map[string]any) unstructured.Unstructured {
	binding := makeVAPB(name, "p", []string{"Deny"})
	if matchResources != nil {
		binding.Object["spec"].(map[string]any)["matchResources"] = matchResources
	}
	return binding
}

func rulesCoverage(t *testing.T, bindings []unstructured.Unstructured, res ResourceInfo, namespaceLabels map[string]map[string]string) ResourceCoverage {
	t.Helper()
	coverage := BuildCoverage(
		[]unstructured.Unstructured{makeVAP("p", rulesControl)},
		bindings,
		map[string][]ResourceInfo{rulesControl: {res}},
		namespaceLabels,
	)
	require.Contains(t, coverage, rulesControl)
	require.True(t, coverage[rulesControl].Bound)
	require.Len(t, coverage[rulesControl].Resources, 1)
	return coverage[rulesControl].Resources[0]
}

var (
	rulesPod        = ResourceInfo{ResourceID: "pod", APIVersion: "v1", Kind: "Pod", Name: "web", Namespace: "default"}
	rulesDeployment = ResourceInfo{ResourceID: "deploy", APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "default"}
	rulesNamespace  = ResourceInfo{ResourceID: "ns", APIVersion: "v1", Kind: "Namespace", Name: "default"}
	rulesClusterRol = ResourceInfo{ResourceID: "cr", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "admin"}
)

func TestCoverageHonorsBindingResourceRules(t *testing.T) {
	deploymentsOnly := map[string]any{"resourceRules": []any{resourceRule("apps", "v1", "deployments", nil)}}
	excludePods := map[string]any{"excludeResourceRules": []any{resourceRule("", "v1", "pods", nil)}}

	for _, tc := range []struct {
		name           string
		matchResources map[string]any
		resource       ResourceInfo
		covered        bool
		reason         string
	}{
		{name: "deployment-only binding does not cover a pod", matchResources: deploymentsOnly, resource: rulesPod,
			reason: "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "deployment-only binding covers a deployment", matchResources: deploymentsOnly, resource: rulesDeployment, covered: true},
		{name: "excludeResourceRules drops the pod", matchResources: excludePods, resource: rulesPod,
			reason: "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "excludeResourceRules keeps a deployment", matchResources: excludePods, resource: rulesDeployment, covered: true},
		{name: "exclusion wins over an inclusion of the same resource", resource: rulesPod,
			matchResources: map[string]any{
				"resourceRules":        []any{resourceRule("", "v1", "pods", nil)},
				"excludeResourceRules": []any{resourceRule("", "v1", "pods", nil)},
			},
			reason: "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "a rule restricted to resourceNames skips another name", resource: rulesPod,
			matchResources: map[string]any{"resourceRules": []any{resourceRule("", "v1", "pods", map[string]any{"resourceNames": []any{"api"}})}},
			reason:         "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "a rule for DELETE only does not cover the create the scan models", resource: rulesPod,
			matchResources: map[string]any{"resourceRules": []any{map[string]any{
				"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"DELETE"}, "resources": []any{"pods"},
			}}},
			reason: "binding resourceRules/excludeResourceRules do not match the resource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesCoverage(t, []unstructured.Unstructured{bindingWithMatchResources("b", tc.matchResources)}, tc.resource, nil)
			assert.Equal(t, tc.covered, got.Covered)
			assert.Equal(t, tc.reason, got.Reason)
		})
	}
}

// A binding that narrows no resources must keep the coverage it had before
// resource rules were evaluated.
func TestCoverageWithoutBindingResourceRulesIsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name           string
		matchResources map[string]any
	}{
		{name: "no matchResources"},
		{name: "empty matchResources", matchResources: map[string]any{}},
		{name: "empty rule lists", matchResources: map[string]any{"resourceRules": []any{}, "excludeResourceRules": []any{}}},
		{name: "matchPolicy alone", matchResources: map[string]any{"matchPolicy": "Exact"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := bindingWithMatchResources("b", tc.matchResources)
			scope, err := resolveBindingScope(binding)
			require.NoError(t, err)
			assert.Nil(t, scope.rules, "a binding that narrows no resources must not get a rule matcher")
			for _, res := range []ResourceInfo{rulesPod, rulesDeployment, rulesNamespace, rulesClusterRol} {
				got := rulesCoverage(t, []unstructured.Unstructured{binding}, res, nil)
				assert.True(t, got.Covered, res.Kind)
				assert.Empty(t, got.Reason, res.Kind)
			}
		})
	}
}

// Several bindings for one policy are alternatives: one that covers the
// resource is enough, whatever the others' rules say.
func TestCoverageBindingRulesAcrossBindings(t *testing.T) {
	got := rulesCoverage(t, []unstructured.Unstructured{
		bindingWithMatchResources("deployments", map[string]any{"resourceRules": []any{resourceRule("apps", "v1", "deployments", nil)}}),
		bindingWithMatchResources("pods", map[string]any{"resourceRules": []any{resourceRule("", "v1", "pods", nil)}}),
	}, rulesPod, nil)
	assert.True(t, got.Covered)
	assert.Empty(t, got.Reason)
}

func TestCoverageBindingRulesMatchPolicy(t *testing.T) {
	// The rule names the deployments resource, but in a group and version
	// the object is not in. Only the cluster knows whether extensions/v1beta1
	// deployments are equivalent to apps/v1 ones.
	otherGroupVersion := []any{resourceRule("extensions", "v1beta1", "deployments", nil)}

	for _, tc := range []struct {
		name           string
		matchResources map[string]any
		covered        bool
		reason         string
	}{
		{name: "unset matchPolicy defaults to Equivalent and is uncertain",
			matchResources: map[string]any{"resourceRules": otherGroupVersion},
			reason:         "binding resource rules could not be evaluated: "},
		{name: "Equivalent is uncertain",
			matchResources: map[string]any{"matchPolicy": "Equivalent", "resourceRules": otherGroupVersion},
			reason:         "binding resource rules could not be evaluated: "},
		{name: "Exact does not match another group version",
			matchResources: map[string]any{"matchPolicy": "Exact", "resourceRules": otherGroupVersion},
			reason:         "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "Exact matches the object's own group version",
			matchResources: map[string]any{"matchPolicy": "Exact", "resourceRules": []any{resourceRule("apps", "v1", "deployments", nil)}},
			covered:        true},
		{name: "an uncertain exclusion is not credited either",
			matchResources: map[string]any{"excludeResourceRules": otherGroupVersion},
			reason:         "binding resource rules could not be evaluated: "},
		{name: "an exclusion under Exact for another group version keeps the deployment",
			matchResources: map[string]any{"matchPolicy": "Exact", "excludeResourceRules": otherGroupVersion},
			covered:        true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesCoverage(t, []unstructured.Unstructured{bindingWithMatchResources("b", tc.matchResources)}, rulesDeployment, nil)
			assert.Equal(t, tc.covered, got.Covered)
			if tc.covered {
				assert.Empty(t, got.Reason)
				return
			}
			assert.Contains(t, got.Reason, tc.reason)
		})
	}
}

func TestCoverageBindingRulesScope(t *testing.T) {
	namespaced := map[string]any{"scope": "Namespaced"}
	cluster := map[string]any{"scope": "Cluster"}
	crd := ResourceInfo{ResourceID: "crd", APIVersion: "example.com/v1", Kind: "Widget", Name: "w"}

	for _, tc := range []struct {
		name     string
		rule     any
		resource ResourceInfo
		covered  bool
		reason   string
	}{
		{name: "namespaced scope covers a pod", rule: resourceRule("", "v1", "pods", namespaced), resource: rulesPod, covered: true},
		{name: "cluster scope does not cover a pod", rule: resourceRule("", "v1", "pods", cluster), resource: rulesPod,
			reason: "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "cluster scope covers a cluster role", rule: resourceRule("rbac.authorization.k8s.io", "v1", "clusterroles", cluster),
			resource: rulesClusterRol, covered: true},
		{name: "namespaced scope does not cover a cluster role", rule: resourceRule("rbac.authorization.k8s.io", "v1", "clusterroles", namespaced),
			resource: rulesClusterRol, reason: "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "cluster scope covers a namespace", rule: resourceRule("", "v1", "namespaces", cluster), resource: rulesNamespace, covered: true},
		{name: "an unknown kind's scope leaves a scoped rule uncertain", rule: resourceRule("example.com", "v1", "widgets", namespaced),
			resource: crd, reason: "binding resource rules could not be evaluated: "},
		{name: "an unscoped rule needs no scope for an unknown kind", rule: resourceRule("example.com", "v1", "widgets", nil),
			resource: crd, covered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := bindingWithMatchResources("b", map[string]any{"matchPolicy": "Exact", "resourceRules": []any{tc.rule}})
			got := rulesCoverage(t, []unstructured.Unstructured{binding}, tc.resource, nil)
			assert.Equal(t, tc.covered, got.Covered)
			if tc.covered {
				assert.Empty(t, got.Reason)
				return
			}
			assert.Contains(t, got.Reason, tc.reason)
		})
	}
}

// The selectors keep deciding first and keep their own reasons; a matching
// rule does not override them.
func TestCoverageBindingRulesAndSelectors(t *testing.T) {
	deployments := []any{resourceRule("apps", "v1", "deployments", nil)}
	labelled := rulesDeployment
	labelled.Labels = map[string]string{"tier": "critical"}
	nsLabels := map[string]map[string]string{"default": {"env": "dev"}}

	for _, tc := range []struct {
		name           string
		matchResources map[string]any
		resource       ResourceInfo
		covered        bool
		reason         string
	}{
		{name: "namespaceSelector excludes despite a matching rule", resource: labelled,
			matchResources: map[string]any{"namespaceSelector": matchLabels("env", "prod"), "resourceRules": deployments},
			reason:         "namespaceSelector does not match the resource's namespace"},
		{name: "objectSelector excludes despite a matching rule", resource: labelled,
			matchResources: map[string]any{"objectSelector": matchLabels("tier", "internal"), "resourceRules": deployments},
			reason:         "objectSelector does not match the resource's labels"},
		{name: "both selectors and the rule match", resource: labelled, covered: true,
			matchResources: map[string]any{
				"namespaceSelector": matchLabels("env", "dev"),
				"objectSelector":    matchLabels("tier", "critical"),
				"resourceRules":     deployments,
			}},
		{name: "matching selectors do not override a non-matching rule", resource: rulesPod,
			matchResources: map[string]any{"namespaceSelector": matchLabels("env", "dev"), "resourceRules": deployments},
			reason:         "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "a cluster-scoped resource passing the namespaceSelector is still held to the rules", resource: rulesClusterRol,
			matchResources: map[string]any{"namespaceSelector": matchLabels("env", "prod"), "resourceRules": deployments},
			reason:         "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "a namespace matched on its own labels is still held to the rules", resource: ResourceInfo{
			ResourceID: "ns", APIVersion: "v1", Kind: "Namespace", Name: "prod", Labels: map[string]string{"env": "prod"}},
			matchResources: map[string]any{"namespaceSelector": matchLabels("env", "prod"), "resourceRules": deployments},
			reason:         "binding resourceRules/excludeResourceRules do not match the resource"},
		{name: "a cluster-scoped resource still passes the namespaceSelector before its rule", resource: rulesClusterRol, covered: true,
			matchResources: map[string]any{
				"namespaceSelector": matchLabels("env", "prod"),
				"resourceRules":     []any{resourceRule("rbac.authorization.k8s.io", "v1", "clusterroles", nil)},
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesCoverage(t, []unstructured.Unstructured{bindingWithMatchResources("b", tc.matchResources)}, tc.resource, nsLabels)
			assert.Equal(t, tc.covered, got.Covered)
			assert.Equal(t, tc.reason, got.Reason)
		})
	}
}

// generatedBinding builds a binding the way `kubescape vap
// create-policy-binding` does (cmd/vap createPolicyBinding): an always-present
// matchResources, an optional namespaceSelector, and resource rules with
// operations "*", serialized to YAML and read back as a live object would be.
func generatedBinding(t *testing.T, namespaces []string, rules ...admissionv1.NamedRuleWithOperations) unstructured.Unstructured {
	t.Helper()
	binding := &admissionv1.ValidatingAdmissionPolicyBinding{}
	binding.APIVersion = "admissionregistration.k8s.io/v1"
	binding.Kind = "ValidatingAdmissionPolicyBinding"
	binding.Name = "generated"
	binding.Spec.PolicyName = "p"
	binding.Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Deny}
	binding.Spec.MatchResources = &admissionv1.MatchResources{}
	if len(namespaces) > 0 {
		binding.Spec.MatchResources.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   namespaces,
			}},
		}
	}
	binding.Spec.MatchResources.ResourceRules = rules
	out, err := yaml.Marshal(binding)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, yaml.Unmarshal(out, &obj))
	return unstructured.Unstructured{Object: obj}
}

func generatedRule(group, version, resource string) admissionv1.NamedRuleWithOperations {
	return admissionv1.NamedRuleWithOperations{
		RuleWithOperations: admissionv1.RuleWithOperations{
			Operations: []admissionv1.OperationType{admissionv1.OperationAll},
			Rule: admissionv1.Rule{
				APIGroups:   []string{group},
				APIVersions: []string{version},
				Resources:   []string{resource},
			},
		},
	}
}

// Coverage and the CEL engine read the same binding; they must agree on
// which scanned objects it binds. The CEL matcher is the reference here, so
// this only proves agreement on these fixtures, not Kubernetes conformance.
func TestCoverageAgreesWithCELBindingScopeOnGeneratedBindings(t *testing.T) {
	namespaceObjects := map[string]map[string]any{
		"default":     {"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "default"}},
		"kube-system": {"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "kube-system"}},
	}
	namespaceLabels := map[string]map[string]string{"default": {}, "kube-system": {}}
	systemPod := ResourceInfo{ResourceID: "sys-pod", APIVersion: "v1", Kind: "Pod", Name: "dns", Namespace: "kube-system"}
	resources := []ResourceInfo{rulesPod, rulesDeployment, systemPod, rulesNamespace, rulesClusterRol}

	bindings := map[string]unstructured.Unstructured{
		"--resource-rule apps/v1/deployments": generatedBinding(t, nil, generatedRule("apps", "v1", "deployments")),
		"--resource-rule /v1/pods":            generatedBinding(t, nil, generatedRule("", "v1", "pods")),
		"--resource-rule apps/v1/deployments --resource-rule /v1/pods": generatedBinding(t, nil,
			generatedRule("apps", "v1", "deployments"), generatedRule("", "v1", "pods")),
		"--resource-rule '*/*/*'":                         generatedBinding(t, nil, generatedRule("*", "*", "*")),
		"--namespace default --resource-rule /v1/pods":    generatedBinding(t, []string{"default"}, generatedRule("", "v1", "pods")),
		"--resource-rule rbac.../v1/clusterroles":         generatedBinding(t, nil, generatedRule("rbac.authorization.k8s.io", "v1", "clusterroles")),
		"--namespace default (no --resource-rule)":        generatedBinding(t, []string{"default"}),
		"--resource-rule /v1/namespaces --namespace kube": generatedBinding(t, []string{"kube-system"}, generatedRule("", "v1", "namespaces")),
	}

	for name, binding := range bindings {
		scope, err := cel.ParseBindingScope(binding.Object)
		require.NoError(t, err, name)
		for _, res := range resources {
			obj := res.ruleObject()
			var nsObj map[string]any
			if res.Namespace != "" {
				nsObj = namespaceObjects[res.Namespace]
			}
			want, celErr := scope.Covers(obj, nsObj)
			require.NoError(t, celErr, "%s / %s: fixtures must be decidable by the CEL matcher", name, res.ResourceID)

			got := rulesCoverage(t, []unstructured.Unstructured{binding}, res, namespaceLabels)
			assert.Equal(t, want, got.Covered, "%s / %s: coverage disagrees with cel.BindingScope.Covers (reason %q)", name, res.ResourceID, got.Reason)
		}
	}
}

// Coverage matches rules against the collected object itself, so a CRD's
// declared plural reaches the rule even though the kind cannot be guessed to
// it.
func TestCollectedCoverageResourcesCarryTheObjectForRules(t *testing.T) {
	wl := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Octopus",
		"metadata": map[string]any{
			"name":        "inky",
			"namespace":   "default",
			"annotations": map[string]any{"kubescape.io/resource-plural": "octopi"},
		},
	})
	resourceID := wl.GetID()
	byControl := CollectFailingResourcesByControl(nil, map[string]resourcesresults.Result{
		resourceID: {
			ResourceID: resourceID,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: rulesControl, Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
			},
		},
	}, map[string]workloadinterface.IMetadata{resourceID: wl})
	require.Len(t, byControl[rulesControl], 1)
	collected := byControl[rulesControl][0]
	require.NotNil(t, collected.Object, "the collected resource must carry its object for rule matching")

	octopi := bindingWithMatchResources("b", map[string]any{"matchPolicy": "Exact", "resourceRules": []any{resourceRule("example.com", "v1", "octopi", nil)}})
	got := rulesCoverage(t, []unstructured.Unstructured{octopi}, collected, nil)
	assert.True(t, got.Covered, "the annotated plural must reach the rule: %s", got.Reason)

	// Without the object the plural can only be guessed, and the guess misses.
	identityOnly := collected
	identityOnly.Object = nil
	got = rulesCoverage(t, []unstructured.Unstructured{octopi}, identityOnly, nil)
	assert.False(t, got.Covered)
	assert.Equal(t, "binding resourceRules/excludeResourceRules do not match the resource", got.Reason)
}

// A binding whose rules cannot be decoded is malformed, as one with an
// unparsable selector is: it covers nothing rather than everything.
func TestCoverageMalformedBindingRulesCoverNothing(t *testing.T) {
	for name, matchResources := range map[string]map[string]any{
		"malformed rule field":            {"resourceRules": []any{map[string]any{"apiGroups": "apps"}}},
		"resourceRules is not a list":     {"resourceRules": "deployments"},
		"excludeResourceRules not a list": {"excludeResourceRules": map[string]any{"resources": []any{"pods"}}},
	} {
		t.Run(name, func(t *testing.T) {
			binding := bindingWithMatchResources("b", matchResources)
			_, err := resolveBindingScope(binding)
			require.Error(t, err)

			got := rulesCoverage(t, []unstructured.Unstructured{binding}, rulesDeployment, nil)
			assert.False(t, got.Covered)
			assert.Equal(t, "no binding's scope covers this resource", got.Reason)
		})
	}
}
