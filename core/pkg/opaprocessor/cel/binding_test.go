package cel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/policy/matching"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func bindingWith(matchResources map[string]any) map[string]any {
	spec := map[string]any{"policyName": "p"}
	if matchResources != nil {
		spec["matchResources"] = matchResources
	}
	return map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": "b"},
		"spec":       spec,
	}
}

func TestParseBindingScope(t *testing.T) {
	t.Run("no matchResources", func(t *testing.T) {
		scope, err := ParseBindingScope(bindingWith(nil))
		require.NoError(t, err)
		assert.Nil(t, scope)
		covered, err := scope.Covers(map[string]any{"apiVersion": "v1", "kind": "Pod"}, nil)
		require.NoError(t, err)
		assert.True(t, covered)
	})

	t.Run("an unparsable selector is an error", func(t *testing.T) {
		_, err := ParseBindingScope(bindingWith(map[string]any{
			"namespaceSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "env", "operator": "Bogus"}}},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespaceSelector")
	})

	t.Run("a malformed matchResources is an error", func(t *testing.T) {
		_, err := ParseBindingScope(bindingWith(map[string]any{"resourceRules": "pods"}))
		require.Error(t, err)
	})
}

// apiserverCriteria adapts MatchResources to the apiserver matcher's input.
type apiserverCriteria struct {
	mr admissionregistrationv1.MatchResources
}

func (c apiserverCriteria) GetParsedNamespaceSelector() (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(c.mr.NamespaceSelector)
}

func (c apiserverCriteria) GetParsedObjectSelector() (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(c.mr.ObjectSelector)
}

func (c apiserverCriteria) GetMatchResources() admissionregistrationv1.MatchResources { return c.mr }

// TestBindingScopeMatchesApiserver compares BindingScope.Covers with the
// apiserver's own policy matcher (the one BindingMatches calls) for every
// combination of the selectors and rules below, against namespaced,
// cluster-scoped and Namespace objects, as a CREATE. The matchResources are
// given in their apiserver-defaulted form, since that is how a live binding is
// read back.
func TestBindingScopeMatchesApiserver(t *testing.T) {
	namespaces := map[string]map[string]string{
		"prod": {"env": "prod"},
		"dev":  {"env": "dev"},
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	var clientObjects []runtime.Object
	namespaceObjects := map[string]map[string]any{}
	for name, nsLabels := range namespaces {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: nsLabels}}
		require.NoError(t, indexer.Add(ns))
		clientObjects = append(clientObjects, ns)
		namespaceObjects[name] = namespaceObject(name, nsLabels)
	}
	matcher := matching.NewMatcher(corelisters.NewNamespaceLister(indexer), fake.NewClientset(clientObjects...))
	objectInterfaces := admission.NewObjectInterfacesFromScheme(runtime.NewScheme())

	type object struct {
		obj map[string]any
		gvr schema.GroupVersionResource
	}
	objects := map[string]object{
		"trusted pod in prod": {
			obj: workload("v1", "Pod", "p1", "prod", map[string]any{"tier": "trusted"}),
			gvr: schema.GroupVersionResource{Version: "v1", Resource: "pods"},
		},
		"pod in dev": {
			obj: workload("v1", "Pod", "p2", "dev", nil),
			gvr: schema.GroupVersionResource{Version: "v1", Resource: "pods"},
		},
		"deployment in prod": {
			obj: workload("apps/v1", "Deployment", "d1", "prod", nil),
			gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		},
		"namespace prod": {
			obj: namespaceObject("prod", namespaces["prod"]),
			gvr: schema.GroupVersionResource{Version: "v1", Resource: "namespaces"},
		},
		"cluster role": {
			obj: workload("rbac.authorization.k8s.io/v1", "ClusterRole", "cr1", "", nil),
			gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"},
		},
	}

	rule := func(group, version, resource string) admissionregistrationv1.NamedRuleWithOperations {
		return admissionregistrationv1.NamedRuleWithOperations{RuleWithOperations: admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
			Rule: admissionregistrationv1.Rule{
				APIGroups: []string{group}, APIVersions: []string{version}, Resources: []string{resource},
			},
		}}
	}
	namespaceSelectors := map[string]*metav1.LabelSelector{
		"any namespace": {},
		"env=prod":      {MatchLabels: map[string]string{"env": "prod"}},
		"env notin prod": {MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"prod"}},
		}},
	}
	objectSelectors := map[string]*metav1.LabelSelector{
		"any object":   {},
		"tier=trusted": {MatchLabels: map[string]string{"tier": "trusted"}},
	}
	resourceRules := map[string][]admissionregistrationv1.NamedRuleWithOperations{
		"no resourceRules": nil,
		"pods":             {rule("", "v1", "pods")},
		"deployments":      {rule("apps", "v1", "deployments")},
		"everything":       {rule("*", "*", "*")},
	}
	excludeRules := map[string][]admissionregistrationv1.NamedRuleWithOperations{
		"no exclusions":  nil,
		"excluding pods": {rule("", "v1", "pods")},
	}

	equivalent := admissionregistrationv1.Equivalent
	cases := 0
	for nsName, nsSelector := range namespaceSelectors {
		for objName, objSelector := range objectSelectors {
			for rulesName, rules := range resourceRules {
				for excludeName, excludes := range excludeRules {
					mr := admissionregistrationv1.MatchResources{
						NamespaceSelector:    nsSelector,
						ObjectSelector:       objSelector,
						ResourceRules:        rules,
						ExcludeResourceRules: excludes,
						MatchPolicy:          &equivalent,
					}
					raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&mr)
					require.NoError(t, err)
					scope, err := ParseBindingScope(bindingWith(raw))
					require.NoError(t, err)

					for name, o := range objects {
						cases++
						label := fmt.Sprintf("%s / %s / %s / %s / %s", nsName, objName, rulesName, excludeName, name)

						u := &unstructured.Unstructured{Object: o.obj}
						namespace := u.GetNamespace()
						if o.gvr.Resource == "namespaces" {
							namespace = u.GetName() // the apiserver sets it to the namespace's own name
						}
						attr := admission.NewAttributesRecord(u, nil, u.GroupVersionKind(), namespace, u.GetName(), o.gvr, "", admission.Create, &metav1.CreateOptions{}, false, nil)
						want, _, _, err := matcher.Matches(attr, objectInterfaces, apiserverCriteria{mr})
						require.NoError(t, err, label)

						got, err := scope.Covers(o.obj, namespaceObjects[u.GetNamespace()])
						require.NoError(t, err, label)
						assert.Equal(t, want, got, label)
					}
				}
			}
		}
	}
	assert.Equal(t, 240, cases)
}

// TestBindingScopeUncollectedNamespace covers the one input the scan may lack:
// a non-empty namespaceSelector on a namespaced object whose Namespace was not
// collected cannot be answered, unless another criterion already rules the
// object out.
func TestBindingScopeUncollectedNamespace(t *testing.T) {
	scope, err := ParseBindingScope(bindingWith(map[string]any{
		"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
		"objectSelector":    map[string]any{"matchLabels": map[string]any{"tier": "trusted"}},
	}))
	require.NoError(t, err)

	_, err = scope.Covers(workload("v1", "Pod", "p", "orphan", map[string]any{"tier": "trusted"}), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `namespace "orphan" was not collected`)

	covered, err := scope.Covers(workload("v1", "Pod", "p", "orphan", nil), nil)
	require.NoError(t, err, "the objectSelector already rules the pod out")
	assert.False(t, covered)

	covered, err = scope.Covers(workload("rbac.authorization.k8s.io/v1", "ClusterRole", "cr", "", map[string]any{"tier": "trusted"}), nil)
	require.NoError(t, err, "a namespaceSelector never exempts a cluster-scoped object")
	assert.True(t, covered)
}

func workload(apiVersion, kind, name, namespace string, objLabels map[string]any) map[string]any {
	metadata := map[string]any{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	if objLabels != nil {
		metadata["labels"] = objLabels
	}
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": metadata}
}

func namespaceObject(name string, nsLabels map[string]string) map[string]any {
	l := map[string]any{}
	for k, v := range nsLabels {
		l[k] = v
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": name, "labels": l},
	}
}
