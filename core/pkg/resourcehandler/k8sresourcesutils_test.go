package resourcehandler

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestGetK8sResources(t *testing.T) {
	// getK8sResources
}
func TestSetResourceMap(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	framework := reporthandling.MockFrameworkA()
	k8sResources := setK8sResourceMap([]reporthandling.Framework{*framework})
	resources := k8sinterface.ResourceGroupToString("*", "v1", "Pod")
	if len(resources) == 0 {
		t.Error("expected resources")
	}
	_, ok := (*k8sResources)[resources[0]]
	if !ok {
		t.Errorf("missing: 'apps'. k8sResources: %v", k8sResources)
	}

}
func TestSsEmptyImgVulns(t *testing.T) {
	ksResourcesMap := make(cautils.KSResources, 0)
	ksResourcesMap["container.googleapis.com/v1"] = []string{"fsdfds"}
	assert.Equal(t, true, isEmptyImgVulns(ksResourcesMap))

	ksResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{"dada"}
	assert.Equal(t, false, isEmptyImgVulns(ksResourcesMap))

	ksResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{}
	ksResourcesMap["bla"] = []string{"blu"}
	assert.Equal(t, true, isEmptyImgVulns(ksResourcesMap))
}

func TestInsertK8sResources(t *testing.T) {
	// insertK8sResources
	k8sResources := make(map[string]map[string]map[string]interface{})
	match1 := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1", "v1beta"},
		Resources:   []string{"pods"},
	}
	match2 := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1"},
		Resources:   []string{"deployments"},
	}
	match3 := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"core"},
		APIVersions: []string{"v1"},
		Resources:   []string{"secrets"},
	}
	insertResources(k8sResources, match1)
	insertResources(k8sResources, match2)
	insertResources(k8sResources, match3)

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
