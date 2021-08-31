package policyhandler

import (
	"github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/armosec/kubescape/cautils/opapolicy"

	"testing"
)

func TestGetK8sResources(t *testing.T) {
	// getK8sResources
}
func TestSetResourceMap(t *testing.T) {
	framework := opapolicy.MockFrameworkA()
	k8sResources := setResourceMap([]opapolicy.Framework{*framework})
	resources := k8sinterface.ResourceGroupToString("*", "v1", "Pod")
	if len(resources) == 0 {
		t.Error("expected resources")
	}
	_, ok := (*k8sResources)[resources[0]]
	if !ok {
		t.Errorf("missing: 'apps'. k8sResources: %v", k8sResources)
	}

}

func TestInsertK8sResources(t *testing.T) {
	// insertK8sResources
	k8sResources := make(map[string]map[string]map[string]interface{})
	match1 := opapolicy.RuleMatchObjects{
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1", "v1beta"},
		Resources:   []string{"pods"},
	}
	match2 := opapolicy.RuleMatchObjects{
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1"},
		Resources:   []string{"deployments"},
	}
	match3 := opapolicy.RuleMatchObjects{
		APIGroups:   []string{"core"},
		APIVersions: []string{"v1"},
		Resources:   []string{"secrets"},
	}
	insertK8sResources(k8sResources, match1)
	insertK8sResources(k8sResources, match2)
	insertK8sResources(k8sResources, match3)

	apiGroup1, ok := k8sResources["apps"]
	if !ok {
		t.Errorf("missing: 'apps'. k8sResources: %v", k8sResources)
		return
	}
	apiVersion1, ok := apiGroup1["v1"]
	if !ok {
		t.Errorf("missing: 'v1'. k8sResources: %v", k8sResources)
		return
	}
	_, ok = apiVersion1["pods"]
	if !ok {
		t.Errorf("missing: 'pods'. k8sResources: %v", k8sResources)
	}
	_, ok = apiVersion1["deployments"]
	if !ok {
		t.Errorf("missing: 'deployments'. k8sResources: %v", k8sResources)
	}
	apiVersion2, ok := apiGroup1["v1beta"]
	if !ok {
		t.Errorf("missing: 'v1beta'. k8sResources: %v", k8sResources)
		return
	}
	_, ok = apiVersion2["pods"]
	if !ok {
		t.Errorf("missing: 'pods'. k8sResources: %v", k8sResources)
	}
	_, ok = k8sResources["core"]
	if !ok {
		t.Errorf("missing: 'core'. k8sResources: %v", k8sResources)
		return
	}
}
