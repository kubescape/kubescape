package fleet

import (
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
)

// stubDiscovery answers ServerPreferredResources with a canned list. Every
// other method is left to the embedded nil interface, which is safe here
// because InitializeMapResources calls nothing else.
type stubDiscovery struct {
	discovery.DiscoveryInterface
	resources []*metav1.APIResourceList
}

// ServerPreferredResources returns the canned list. InitializeMapResources
// reads the API groups through this one call, so nothing else needs answering.
func (s stubDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return s.resources, nil
}

// clusterResources builds a discovery client advertising a single custom
// resource, so a test can tell two clusters' API-group snapshots apart by
// looking up a name that only one of them serves.
func clusterResources(name, kind string) stubDiscovery {
	return stubDiscovery{resources: []*metav1.APIResourceList{{
		GroupVersion: "fleet.example.com/v1",
		APIResources: []metav1.APIResource{{
			Name:       name,
			Kind:       kind,
			Namespaced: true,
			Verbs:      metav1.Verbs{"list", "get"},
		}},
	}}}
}

// TestDiscoveryRefreshFollowsTheScannedCluster pins the half of per-cluster
// isolation that the aggregation layer reads.
//
// Switching context is owned by cautils.EnterClusterContext and has its own
// unit and two-cluster integration tests, so this does not re-test it. What it
// guards is the API-group snapshot: control evaluation resolves resources
// through it, so a run that scans several contexts in one process needs it to
// follow the cluster currently being scanned.
//
// It used to work the other way round. InitializeMapResources returned early
// once the map had been populated ("load discovery data only if the map is
// empty"), so a second cluster kept resolving through the first cluster's
// snapshot; the fix was to treat an explicitly supplied discovery client as
// authoritative. If a future k8s-interface bump reintroduces the early return,
// this fails here rather than surfacing later as a fleet report that quietly
// describes the wrong cluster.
func TestDiscoveryRefreshFollowsTheScannedCluster(t *testing.T) {
	// The resource map and the context name are process-global, so this test
	// must not run in parallel with anything else that touches them.
	//
	// Both are restored afterwards. Leaving the map holding this test's
	// invented CRDs would let a later test resolve a resource that exists in no
	// cluster, or fail depending on the order the package's tests happen to run
	// in. InitializeMapResourcesMock is the supported reset: it swaps in the
	// standard mock snapshot, which is the state the map holds for any test
	// that never populated it explicitly.
	previousContext := k8sinterface.GetContextName()
	t.Cleanup(func() {
		k8sinterface.SetClusterContextName(previousContext)
		k8sinterface.InitializeMapResourcesMock()
	})

	first := clusterResources("firstclusterwidgets", "FirstClusterWidget")
	second := clusterResources("secondclusterwidgets", "SecondClusterWidget")

	leaveFirst := cautils.EnterClusterContext("first-cluster")
	k8sinterface.InitializeMapResources(first)
	_, hasFirst := k8sinterface.GetResourceFromGroupMapping("firstclusterwidgets")
	require.True(t, hasFirst,
		"a cluster's own resources should resolve while it is the active context")
	leaveFirst()

	leaveSecond := cautils.EnterClusterContext("second-cluster")
	defer leaveSecond()
	k8sinterface.InitializeMapResources(second)

	_, hasSecond := k8sinterface.GetResourceFromGroupMapping("secondclusterwidgets")
	assert.True(t, hasSecond,
		"the second cluster's resources are missing: InitializeMapResources is no longer treating an "+
			"explicit discovery client as authoritative, so a scan would resolve resources through the "+
			"previous cluster's snapshot")

	_, stillHasFirst := k8sinterface.GetResourceFromGroupMapping("firstclusterwidgets")
	assert.False(t, stillHasFirst,
		"the first cluster's resources still resolve after switching: the snapshot is being merged "+
			"rather than replaced, which lets one cluster's API groups leak into another cluster's scan")
}

// TestEnterClusterContextRestoresPrevious covers the property the orchestrator
// relies on when it defers leave() around each cluster: whatever context was
// active before a run is active again after it, so a fleet command does not
// leave the process pointed at the last cluster it happened to scan.
func TestEnterClusterContextRestoresPrevious(t *testing.T) {
	previousContext := k8sinterface.GetContextName()
	t.Cleanup(func() { k8sinterface.SetClusterContextName(previousContext) })

	k8sinterface.SetClusterContextName("before-the-run")

	leave := cautils.EnterClusterContext("prod")
	require.Equal(t, "prod", k8sinterface.GetContextName())

	leave()
	assert.Equal(t, "before-the-run", k8sinterface.GetContextName())
}
