package cautils

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLargeCluster(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "2500")

	tests := []struct {
		name        string
		clusterSize int
		want        bool
	}{
		{
			name:        "zero nodes — not large",
			clusterSize: 0,
			want:        false,
		},
		{
			name:        "below threshold — not large",
			clusterSize: 100,
			want:        false,
		},
		{
			name:        "at threshold — not large (exclusive)",
			clusterSize: 2500,
			want:        false,
		},
		{
			name:        "above threshold — large",
			clusterSize: 2501,
			want:        true,
		},
		{
			name:        "well above threshold — large",
			clusterSize: 10000,
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLargeCluster(tt.clusterSize))
		})
	}
}

func TestResourceScope(t *testing.T) {
	tests := []struct {
		name string
		obj  workloadinterface.IMetadata
		want string
	}{
		{
			name: "namespaced resource returns its namespace",
			obj:  mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"mypod","namespace":"mynamespace"}}`),
			want: "mynamespace",
		},
		{
			name: "Namespace kind returns its own name",
			obj:  mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"mynamespace"}}`),
			want: "mynamespace",
		},
		{
			name: "cluster-scoped resource returns clusterScope",
			obj:  mustWorkload(t, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"mynode"}}`),
			want: ClusterScope,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResourceScope(tt.obj))
		})
	}
}

// TestPartitionResources_SmallCluster asserts that a cluster at or below the
// threshold is a single resident batch: the evaluation input stays exactly
// what it was before resources were partitioned at all.
func TestPartitionResources_SmallCluster(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "2500")

	pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a","namespace":"ns-a"}}`)
	node := mustWorkload(t, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-a"}}`)

	k8sResources := K8SResources{
		"/v1/pods":  {pod.GetID()},
		"/v1/nodes": {node.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		pod.GetID():  pod,
		node.GetID(): node,
	}

	resident, batches := PartitionResources(len(allResources), k8sResources, nil, allResources)

	assert.Empty(t, batches, "small clusters must not be split by namespace")
	assert.Equal(t, ClusterScope, resident.Scope)
	assert.Equal(t, 2, resident.Len())
	assert.Equal(t, []string{pod.GetID()}, resident.K8SResources["/v1/pods"])
	assert.Equal(t, []string{node.GetID()}, resident.K8SResources["/v1/nodes"])
}

// TestPartitionResources_LargeCluster asserts the split a large cluster gets:
// namespaced resources in per-namespace batches ordered deterministically,
// everything else resident.
func TestPartitionResources_LargeCluster(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	podB := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-b","namespace":"ns-b"}}`)
	podA := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a","namespace":"ns-a"}}`)
	namespaceA := mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}`)
	clusterRole := mustWorkload(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cr"}}`)

	k8sResources := K8SResources{
		"/v1/pods":       {podB.GetID(), podA.GetID()},
		"/v1/namespaces": {namespaceA.GetID()},
		"rbac.authorization.k8s.io/v1/clusterroles": {clusterRole.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		podA.GetID():        podA,
		podB.GetID():        podB,
		namespaceA.GetID():  namespaceA,
		clusterRole.GetID(): clusterRole,
	}

	resident, batches := PartitionResources(len(allResources), k8sResources, nil, allResources)

	// only the ClusterRole is resident: a Namespace object belongs to the
	// scope it names, so it is evaluated together with its own workloads
	require.Equal(t, 1, resident.Len())
	assert.Contains(t, resident.AllResources, clusterRole.GetID())

	require.Len(t, batches, 2)
	assert.Equal(t, "ns-a", batches[0].Scope, "batches must be ordered by scope")
	assert.Equal(t, "ns-b", batches[1].Scope)

	assert.Equal(t, []string{podA.GetID()}, batches[0].K8SResources["/v1/pods"])
	assert.Equal(t, []string{namespaceA.GetID()}, batches[0].K8SResources["/v1/namespaces"])
	assert.Equal(t, []string{podB.GetID()}, batches[1].K8SResources["/v1/pods"])
}

// TestPartitionResources_ExternalResourcesAreResident asserts that external
// (cloud / host scanner / API server) objects stay available to every scope.
func TestPartitionResources_ExternalResourcesAreResident(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a","namespace":"ns-a"}}`)
	apiServerInfo := mustWorkload(t, `{"apiVersion":"hostdata.kubescape.cloud/v1beta0","kind":"APIServerInfo","metadata":{"name":"version"}}`)

	k8sResources := K8SResources{"/v1/pods": {pod.GetID()}}
	externalResources := ExternalResources{
		"hostdata.kubescape.cloud/v1beta0/APIServerInfo": {apiServerInfo.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		pod.GetID():           pod,
		apiServerInfo.GetID(): apiServerInfo,
	}

	resident, batches := PartitionResources(len(allResources), k8sResources, externalResources, allResources)

	assert.Contains(t, resident.AllResources, apiServerInfo.GetID())
	assert.Equal(t, []string{apiServerInfo.GetID()},
		resident.ExternalResources["hostdata.kubescape.cloud/v1beta0/APIServerInfo"])
	require.Len(t, batches, 1)
	assert.NotContains(t, batches[0].AllResources, apiServerInfo.GetID())
}

// TestPartitionResources_SkipsUnknownIDs asserts that an index entry with no
// matching object is dropped rather than materialised as a nil resource.
func TestPartitionResources_SkipsUnknownIDs(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "2500")

	pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a","namespace":"ns-a"}}`)

	k8sResources := K8SResources{"/v1/pods": {pod.GetID(), "path/to/nowhere"}}
	allResources := map[string]workloadinterface.IMetadata{pod.GetID(): pod}

	resident, batches := PartitionResources(len(allResources), k8sResources, nil, allResources)

	assert.Empty(t, batches)
	assert.Equal(t, []string{pod.GetID()}, resident.K8SResources["/v1/pods"])
}

func mustWorkload(t *testing.T, raw string) workloadinterface.IMetadata {
	t.Helper()
	workload, err := workloadinterface.NewWorkload([]byte(raw))
	require.NoError(t, err)
	require.NotNil(t, workload)
	return workload
}
