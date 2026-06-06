package resourcehandler

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestSsEmptyImgVulns(t *testing.T) {
	externalResourcesMap := make(cautils.ExternalResources, 0)
	externalResourcesMap["container.googleapis.com/v1"] = []string{"fsdfds"}
	assert.Equal(t, true, isEmptyImgVulns(externalResourcesMap))

	externalResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{"dada"}
	assert.Equal(t, false, isEmptyImgVulns(externalResourcesMap))

	externalResourcesMap["armo.vuln.images/v1/ImageVulnerabilities"] = []string{}
	externalResourcesMap["bla"] = []string{"blu"}
	assert.Equal(t, true, isEmptyImgVulns(externalResourcesMap))
}

// TestSetComplexKSResourceMap_IncludesRuleMatch verifies that setComplexKSResourceMap
// populates resourceToControls from rule.Match (regular K8s resources), not only
// from rule.DynamicMatch. This is required so that when pullResources fails to
// fetch a GVR, SetInfoMapForResources can link the GVR key back to the controls
// that depend on it via mapControlToInfo.
func TestSetComplexKSResourceMap_IncludesRuleMatch(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	controlID := "C-0035"
	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		APIVersions: []string{"v1"},
		Resources:   []string{"clusterrolebindings"},
	}
	rule := reporthandling.PolicyRule{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", "rule-rbac", nil),
		Match:      []reporthandling.RuleMatchObjects{match},
	}
	control := reporthandling.Control{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", "ctrl-rbac", nil),
		ControlID:  controlID,
		Rules:      []reporthandling.PolicyRule{rule},
	}
	framework := reporthandling.Framework{
		Controls: []reporthandling.Control{control},
	}

	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls)

	// At least one GVR key for clusterrolebindings should map to the control.
	found := false
	for _, controlIDs := range resourceToControls {
		for _, id := range controlIDs {
			if id == controlID {
				found = true
			}
		}
	}
	assert.True(t, found, "ResourceToControlsMap should contain the control ID for a rule.Match GVR")
}

// TestSetComplexKSResourceMap_RuleMatchKeyMatchesPullResourcesKey verifies that
// the GVR keys written into resourceToControls by setComplexKSResourceMap use the
// same format as the GroupVersionResourceTriplet strings produced by
// getQueryableResourceMapFromPolicies — the two must match for the InfoMap path
// to correctly link a failed pull to its affected controls.
func TestSetComplexKSResourceMap_RuleMatchKeyMatchesPullResourcesKey(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"clusterrolebindings"},
	}
	rule := reporthandling.PolicyRule{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", "rule-rbac", nil),
		Match:      []reporthandling.RuleMatchObjects{match},
	}
	control := reporthandling.Control{
		PortalBase: *armotypes.MockPortalBase("aaaaaaaa-bbbb-cccc-dddd-000000000001", "ctrl-rbac", nil),
		ControlID:  "C-0035",
		Rules:      []reporthandling.PolicyRule{rule},
	}
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}

	// Keys from ResourceToControlsMap (built by setComplexKSResourceMap).
	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls)

	// Keys from QueryableResources (built by getQueryableResourceMapFromPolicies).
	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{framework},
		nil,
		reporthandling.ScopeCluster,
	)

	// Every QueryableResource GVR that appears in QueryableResources should also
	// appear in resourceToControls so InfoMap lookups succeed.
	for qKey := range queryable {
		_, exists := resourceToControls[qKey]
		assert.True(t, exists,
			"GVR %q is in QueryableResources but missing from ResourceToControlsMap", qKey)
	}
}

func Test_getWorkloadFromScanObject(t *testing.T) {
	// nil input returns nil without error
	workload, err := getWorkloadFromScanObject(nil)
	assert.NoError(t, err)
	assert.Nil(t, workload)

	// valid input returns workload without error
	workload, err = getWorkloadFromScanObject(&objectsenvelopes.ScanObject{
		ApiVersion: "apps/v1",
		Kind:       "Deployment",
		Metadata: objectsenvelopes.ScanObjectMetadata{
			Name:      "test-deployment",
			Namespace: "test-ns",
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, workload)
	assert.Equal(t, "test-ns", workload.GetNamespace())
	assert.Equal(t, "test-deployment", workload.GetName())
	assert.Equal(t, "Deployment", workload.GetKind())
	assert.Equal(t, "apps/v1", workload.GetApiVersion())

	// invalid input returns an error
	workload, err = getWorkloadFromScanObject(&objectsenvelopes.ScanObject{
		ApiVersion: "apps/v1",
		// missing kind
		Metadata: objectsenvelopes.ScanObjectMetadata{
			Name:      "test-deployment",
			Namespace: "test-ns",
		},
	})
	assert.Error(t, err)
	assert.Nil(t, workload)
}
