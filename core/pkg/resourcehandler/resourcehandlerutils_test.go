package resourcehandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func mockMatch(i int) reporthandling.RuleMatchObjects {
	switch i {
	case 1:
		return reporthandling.RuleMatchObjects{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1", "v1beta"},
			Resources:   []string{"Pod"},
		}
	case 2:
		return reporthandling.RuleMatchObjects{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"Deployment", "ReplicaSet"},
		}
	case 3:
		return reporthandling.RuleMatchObjects{
			APIGroups:   []string{"core"},
			APIVersions: []string{"v1"},
			Resources:   []string{"Secret"},
		}
	case 4:
		return reporthandling.RuleMatchObjects{
			APIGroups:     []string{"core"},
			APIVersions:   []string{"v1"},
			Resources:     []string{"Secret"},
			FieldSelector: []string{"metadata.name=secret1", "metadata.name=secret2,metadata.namespace=default"},
		}
	case 5:
		return reporthandling.RuleMatchObjects{
			APIGroups:     []string{"rbac.authorization.k8s.io"},
			APIVersions:   []string{"v1"},
			Resources:     []string{"ClusterRoleBinding", "RoleBinding"},
			FieldSelector: []string{"metadata.name=test123"},
		}
	case 6:
		return reporthandling.RuleMatchObjects{
			APIGroups:     []string{""},
			APIVersions:   []string{"v1"},
			Resources:     []string{"Namespace"},
			FieldSelector: []string{},
		}
	case 7:
		return reporthandling.RuleMatchObjects{
			APIGroups:     []string{""},
			APIVersions:   []string{"v1"},
			Resources:     []string{"Node"},
			FieldSelector: []string{},
		}

	default:
		panic("invalid index")
	}
}

func mockRule(ruleName string, matches []reporthandling.RuleMatchObjects, ruleRego string) reporthandling.PolicyRule {
	rule := reporthandling.PolicyRule{
		PortalBase:   *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", ruleName, nil),
		RuleLanguage: reporthandling.RegoLanguage,
		Match:        matches,
		RuleDependencies: []reporthandling.RuleDependency{
			{
				PackageName: "kubernetes.api.client",
			},
		},
	}
	if ruleRego != "" {
		rule.Rule = ruleRego
	} else {
		rule.Rule = reporthandling.MockRegoPrivilegedPods()
	}
	return rule
}

func mockControl(controlName string, rules []reporthandling.PolicyRule) reporthandling.Control {
	return reporthandling.Control{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", controlName, nil),
		Rules:      rules,
	}

}

func mockFramework(frameworkName string, controls []reporthandling.Control) *reporthandling.Framework {
	return &reporthandling.Framework{
		PortalBase:   *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", frameworkName, nil),
		CreationTime: "",
		Description:  "mock framework description",
		Controls:     controls,
	}
}

func mockWorkload(apiVersion, kind, namespace, name string) workloadinterface.IWorkload {
	mock := workloadinterface.NewWorkloadMock(nil)
	mock.SetKind(kind)
	mock.SetApiVersion(apiVersion)
	mock.SetName(name)
	mock.SetNamespace(namespace)

	if ok := k8sinterface.IsTypeWorkload(mock.GetObject()); !ok {
		panic("mocked object is not a valid workload")
	}

	return mock
}

// TestAddSingleResourceToResourceMaps_UnresolvableApiVersion is a defense-in-
// depth guard (see the comment above the `groups :=` guard in
// resourcehandlerutils.go for why this is unreachable via current callers).
// It bypasses the IsTypeWorkload gate deliberately (unlike mockWorkload,
// which enforces it) to pin the function's own behavior on its own.
func TestAddSingleResourceToResourceMaps_UnresolvableApiVersion(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	obj := map[string]any{
		"apiVersion": "v2", // no known group serves "deployments" at version "v2"
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	}
	wl := workloadinterface.NewWorkloadObj(obj)
	k8sResources := cautils.K8SResources{}
	allResources := map[string]workloadinterface.IMetadata{}

	assert.NotPanics(t, func() {
		addSingleResourceToResourceMaps(k8sResources, allResources, wl)
	})

	// The resource is still recorded for lookup purposes (e.g. by ID)...
	assert.Contains(t, allResources, wl.GetID())
	// ...but is not added under any resource group, since none could be resolved.
	for group, ids := range k8sResources {
		assert.NotContains(t, ids, wl.GetID(), "workload with unresolvable apiVersion must not be added under group %q", group)
	}
}

func TestAddSingleResourceToResourceMaps_KnownApiVersion(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	wl := mockWorkload("apps/v1", "Deployment", "default", "nginx")
	k8sResources := cautils.K8SResources{}
	allResources := map[string]workloadinterface.IMetadata{}

	addSingleResourceToResourceMaps(k8sResources, allResources, wl)

	assert.Contains(t, allResources, wl.GetID())
	assert.Contains(t, k8sResources["apps/v1/deployments"], wl.GetID())
}

func TestAddSingleResourceToResourceMaps_NilWorkload(t *testing.T) {
	k8sResources := cautils.K8SResources{}
	allResources := map[string]workloadinterface.IMetadata{}

	assert.NotPanics(t, func() {
		addSingleResourceToResourceMaps(k8sResources, allResources, nil)
	})
	assert.Empty(t, allResources)
	assert.Empty(t, k8sResources)
}

func TestGetQueryableResourceMapFromPolicies(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	testCases := []struct {
		name                   string
		workload               workloadinterface.IWorkload
		controls               []reporthandling.Control
		expectedResourceGroups []string
		expectedExcludedRules  []string
	}{
		{
			name:     "no workload - all resources groups are queryable",
			workload: nil,
			controls: []reporthandling.Control{
				mockControl("1", []reporthandling.PolicyRule{
					mockRule("rule-a", []reporthandling.RuleMatchObjects{
						mockMatch(1), mockMatch(2), mockMatch(3), mockMatch(4),
					}, ""),
					mockRule("rule-b", []reporthandling.RuleMatchObjects{
						mockMatch(6),
					}, ""),
				}),
			},
			expectedExcludedRules: []string{},
			expectedResourceGroups: []string{
				"/v1/namespaces",
				"apps/v1/deployments",
				"apps/v1/pods",
				"apps/v1/replicasets",
				"apps/v1beta/pods",
				"core/v1/secrets",
				"core/v1/secrets/metadata.name=secret1",
				"core/v1/secrets/metadata.name=secret2,metadata.namespace=default",
			},
		},
		{
			name:     "workload - Namespace",
			workload: mockWorkload("v1", "Namespace", "", "ns1"),
			controls: []reporthandling.Control{
				mockControl("1", []reporthandling.PolicyRule{
					mockRule("rule-a", []reporthandling.RuleMatchObjects{
						mockMatch(1), mockMatch(2), mockMatch(3), mockMatch(4),
					}, ""),
					mockRule("rule-b", []reporthandling.RuleMatchObjects{
						mockMatch(6), mockMatch(3), mockMatch(2), mockMatch(7),
					}, ""),
				}),
			},
			expectedExcludedRules: []string{
				"rule-a",
			},
			expectedResourceGroups: []string{
				"/v1/nodes",
				"core/v1/secrets/metadata.namespace=ns1",
				"apps/v1/deployments/metadata.namespace=ns1",
				"apps/v1/replicasets/metadata.namespace=ns1",
			},
		},
		{
			name:     "workload - Deployment",
			workload: mockWorkload("apps/v1", "Deployment", "ns1", "deploy1"),
			controls: []reporthandling.Control{
				mockControl("1", []reporthandling.PolicyRule{
					mockRule("rule-b", []reporthandling.RuleMatchObjects{
						mockMatch(6), mockMatch(3), mockMatch(2), mockMatch(7),
					}, ""),
				}),
			},
			expectedExcludedRules: []string{},
			expectedResourceGroups: []string{
				"core/v1/secrets/metadata.namespace=ns1",
				"/v1/namespaces/metadata.name=ns1",
				"/v1/nodes",
			},
		},
		{
			name:     "workload - Node",
			workload: mockWorkload("v1", "Node", "", "node1"),
			controls: []reporthandling.Control{
				mockControl("1", []reporthandling.PolicyRule{
					mockRule("rule-b", []reporthandling.RuleMatchObjects{
						mockMatch(6), mockMatch(3), mockMatch(2), mockMatch(7),
					}, ""),
				}),
			},
			expectedExcludedRules: []string{},
			expectedResourceGroups: []string{
				"core/v1/secrets",
				"/v1/namespaces",
				"apps/v1/deployments",
				"apps/v1/replicasets",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resourceGroups, excludedRulesMap := getQueryableResourceMapFromPolicies([]reporthandling.Framework{*mockFramework("test", testCase.controls)}, testCase.workload, reporthandling.ScopeCluster) // TODO check second param
			assert.Equalf(t, len(testCase.expectedExcludedRules), len(excludedRulesMap), "excludedRulesMap length is not as expected")
			for _, expectedExcludedRuleName := range testCase.expectedExcludedRules {
				assert.Contains(t, excludedRulesMap, expectedExcludedRuleName, "excludedRulesMap does not contain expected rule name")
			}

			assert.Equalf(t, len(testCase.expectedResourceGroups), len(resourceGroups), "queryableResourceMap length is not as expected")
			for _, expected := range testCase.expectedResourceGroups {
				assert.Contains(t, resourceGroups, expected, "queryableResourceMap does not contain expected resource group")
			}
		})
	}
}

func TestUpdateQueryableResourcesMapFromRuleMatchObject(t *testing.T) {
	testCases := []struct {
		name                            string
		matches                         []reporthandling.RuleMatchObjects
		resourcesFilterMap              map[string]bool
		namespace                       string
		expectedQueryableResourceGroups []string
		expectedK8SResourceGroups       []string
	}{
		{
			name: "filter map is nil - query all",
			matches: []reporthandling.RuleMatchObjects{
				mockMatch(1), mockMatch(2), mockMatch(3), mockMatch(4),
			},
			resourcesFilterMap: nil,
			namespace:          "",
			expectedQueryableResourceGroups: []string{
				"apps/v1/pods",
				"apps/v1beta/pods",
				"apps/v1/deployments",
				"apps/v1/replicasets",
				"core/v1/secrets",
				"core/v1/secrets/metadata.name=secret1",
				"core/v1/secrets/metadata.name=secret2,metadata.namespace=default",
			},
			expectedK8SResourceGroups: []string{
				"apps/v1/pods",
				"apps/v1beta/pods",
				"apps/v1/deployments",
				"apps/v1/replicasets",
				"core/v1/secrets",
			},
		},
		{
			name: "filter map not nil - query only secrets and pods",
			matches: []reporthandling.RuleMatchObjects{
				mockMatch(1), mockMatch(2), mockMatch(3), mockMatch(4),
			},
			namespace: "",
			resourcesFilterMap: map[string]bool{
				"Secret":     true,
				"Pod":        true,
				"ReplicaSet": false,
				"Deployment": false,
			},
			expectedQueryableResourceGroups: []string{
				"apps/v1/pods",
				"apps/v1beta/pods",
				"core/v1/secrets",
				"core/v1/secrets/metadata.name=secret1",
				"core/v1/secrets/metadata.name=secret2,metadata.namespace=default",
			},
			expectedK8SResourceGroups: []string{
				"apps/v1/pods",
				"apps/v1beta/pods",
				"core/v1/secrets",
			},
		},
		{
			name: "namespace field selector for namespaced resources",
			matches: []reporthandling.RuleMatchObjects{
				mockMatch(5),
			},
			namespace: "ns1",
			resourcesFilterMap: map[string]bool{
				"RoleBinding":        true,
				"ClusterRoleBinding": true,
			},
			expectedQueryableResourceGroups: []string{

				"rbac.authorization.k8s.io/v1/clusterrolebindings/metadata.name=test123",
				"rbac.authorization.k8s.io/v1/rolebindings/metadata.namespace=ns1,metadata.name=test123",
			},
			expectedK8SResourceGroups: []string{
				"rbac.authorization.k8s.io/v1/clusterrolebindings",
				"rbac.authorization.k8s.io/v1/rolebindings",
			},
		},
		{
			name: "name field selector for Namespace resource",
			matches: []reporthandling.RuleMatchObjects{
				mockMatch(2), mockMatch(6),
			},
			namespace: "ns1",
			resourcesFilterMap: map[string]bool{
				"Deployment": true,
				"ReplicaSet": false,
				"Namespace":  true,
			},
			expectedQueryableResourceGroups: []string{
				"apps/v1/deployments/metadata.namespace=ns1",
				"/v1/namespaces/metadata.name=ns1",
			},
			expectedK8SResourceGroups: []string{
				"apps/v1/deployments",
				"/v1/namespaces",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			queryableResources := make(QueryableResources)
			for i := range testCase.matches {
				updateQueryableResourcesMapFromRuleMatchObject(&testCase.matches[i], testCase.resourcesFilterMap, queryableResources, testCase.namespace)
			}

			assert.Equal(t, len(testCase.expectedQueryableResourceGroups), len(queryableResources))
			for _, resourceGroup := range testCase.expectedQueryableResourceGroups {
				assert.Contains(t, queryableResources, resourceGroup)
			}

			k8sResources := queryableResources.ToK8sResourceMap()
			assert.Equal(t, len(testCase.expectedK8SResourceGroups), len(k8sResources))
			for _, resourceGroup := range testCase.expectedK8SResourceGroups {
				assert.Contains(t, k8sResources, resourceGroup)
			}
		})
	}
}

func TestFilterRuleMatchesForResource(t *testing.T) {
	testCases := []struct {
		resourceKind   string
		matchResources []string
		expectedMap    map[string]bool
	}{
		{
			resourceKind: "Pod",
			matchResources: []string{
				"Node", "Pod", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet", "CronJob", "Job", "PodSecurityPolicy",
			},
			expectedMap: map[string]bool{
				"Node":              true,
				"PodSecurityPolicy": true,
				"Pod":               false,
				"DaemonSet":         false,
				"Deployment":        false,
				"ReplicaSet":        false,
				"StatefulSet":       false,
				"CronJob":           false,
				"Job":               false,
			},
		},
		{
			resourceKind: "Deployment",
			matchResources: []string{
				"Node", "Pod", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet", "CronJob", "Job", "PodSecurityPolicy",
			},
			expectedMap: map[string]bool{
				"Node":              true,
				"PodSecurityPolicy": true,
				"Pod":               false,
				"DaemonSet":         false,
				"Deployment":        false,
				"ReplicaSet":        false,
				"StatefulSet":       false,
				"CronJob":           false,
				"Job":               false,
			},
		},
		{
			resourceKind: "Deployment",
			matchResources: []string{
				"Deployment", "ReplicaSet",
			},
			expectedMap: map[string]bool{
				"Deployment": false,
				"ReplicaSet": false,
			},
		},
		{
			resourceKind: "ReplicaSet",
			matchResources: []string{
				"Node", "Pod", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet", "CronJob", "Job", "PodSecurityPolicy",
			},
			expectedMap: map[string]bool{
				"Node":              true,
				"PodSecurityPolicy": true,
				"Pod":               false,
				"DaemonSet":         false,
				"Deployment":        false,
				"ReplicaSet":        false,
				"StatefulSet":       false,
				"CronJob":           false,
				"Job":               false,
			},
		},
		{
			resourceKind: "ClusterRole",
			matchResources: []string{
				"Node", "Pod", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet", "CronJob", "Job", "PodSecurityPolicy",
			},
			expectedMap: nil, // rule does not apply to workload
		},
		{
			resourceKind: "Node",
			matchResources: []string{
				"Node", "Pod", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet", "CronJob", "Job", "PodSecurityPolicy",
			},
			expectedMap: map[string]bool{
				"Node":              false,
				"PodSecurityPolicy": true,
				"Pod":               true,
				"DaemonSet":         true,
				"Deployment":        true,
				"ReplicaSet":        true,
				"StatefulSet":       true,
				"CronJob":           true,
				"Job":               true,
			},
		},
		{
			resourceKind: "Pod",
			matchResources: []string{
				"PodSecurityPolicy", "Pod",
			},
			expectedMap: map[string]bool{
				"PodSecurityPolicy": true,
				"Pod":               false,
			},
		},
		{
			resourceKind: "Pod",
			matchResources: []string{
				"PodSecurityPolicy", "Pod", "ReplicaSet",
			},
			expectedMap: map[string]bool{
				"PodSecurityPolicy": true,
				"Pod":               false,
				"ReplicaSet":        false,
			},
		},
		{
			resourceKind: "Deployment",
			matchResources: []string{
				"PodSecurityPolicy", "Pod",
			},
			expectedMap: nil, // rule does not apply to workload
		},
		{
			resourceKind: "PodSecurityPolicy",
			matchResources: []string{
				"PodSecurityPolicy", "Pod",
			},
			expectedMap: map[string]bool{
				"PodSecurityPolicy": false,
				"Pod":               true,
			},
		},
	}
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			matches := []reporthandling.RuleMatchObjects{
				{
					Resources: testCase.matchResources,
				},
			}

			result := filterRuleMatchesForResource(testCase.resourceKind, matches)
			if testCase.expectedMap == nil {
				assert.Nil(t, result, "expected nil (rule does not apply to the resource)")
				return
			}

			if !reflect.DeepEqual(result, testCase.expectedMap) {
				t.Errorf("expected %v, got %v", testCase.expectedMap, result)
			}
		})
	}
}
