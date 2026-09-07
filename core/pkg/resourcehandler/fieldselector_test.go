package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestGetNamespacesSelector(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	assert.Equal(t, "", getNamespacesSelector("pods", "", "=="))
	assert.Equal(t, "metadata.namespace==default", getNamespacesSelector("pods", "default", "=="))
	assert.Equal(t, "metadata.namespace==default", getNamespacesSelector("Pod", "default", "=="))
	assert.Equal(t, "", getNamespacesSelector("nodes", "default", "=="))
	assert.Equal(t, "", getNamespacesSelector("Node", "default", "=="))
	assert.Equal(t, "metadata.name==kube-system", getNamespacesSelector("namespaces", "kube-system", "=="))
	assert.Equal(t, "metadata.name==kube-system", getNamespacesSelector("Namespace", "kube-system", "=="))
}

func TestExcludedNamespacesSelectors(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	es := NewExcludeSelector("default,ingress")
	selectors := es.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil)
	assert.Equal(t, 1, len(selectors))
	assert.Equal(t, "metadata.namespace!=default,metadata.namespace!=ingress", selectors[0])

	selectors2 := es.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "namespaces"}, nil)
	assert.Equal(t, 1, len(selectors2))
	assert.Equal(t, "metadata.name!=default,metadata.name!=ingress", selectors2[0])

	esSpace := NewExcludeSelector("default, ingress")
	selectorsSpace := esSpace.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil)
	assert.Equal(t, 1, len(selectorsSpace))
	assert.Equal(t, "metadata.namespace!=default,metadata.namespace!=ingress", selectorsSpace[0])
}

func TestIncludeNamespacesSelectors(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	is := NewIncludeSelector("default,ingress")
	selectors := is.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil)
	assert.Equal(t, 2, len(selectors))
	assert.Equal(t, "metadata.namespace==default", selectors[0])
	assert.Equal(t, "metadata.namespace==ingress", selectors[1])

	selectors2 := is.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "namespaces"}, nil)
	assert.Equal(t, 2, len(selectors2))
	assert.Equal(t, "metadata.name==default", selectors2[0])
	assert.Equal(t, "metadata.name==ingress", selectors2[1])

	isSpace := NewIncludeSelector("default, ingress")
	selectorsSpace := isSpace.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil)
	assert.Equal(t, 2, len(selectorsSpace))
	assert.Equal(t, "metadata.namespace==default", selectorsSpace[0])
	assert.Equal(t, "metadata.namespace==ingress", selectorsSpace[1])

	// Cluster-scoped resources must collapse to a single unfiltered query
	// regardless of how many namespaces were included; otherwise
	// pullSingleResource would LIST the collection once per namespace and
	// duplicate every cluster-scoped object N times in k8sResources[gvr].
	clusterScopedSelectors := is.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "nodes"}, nil)
	assert.Equal(t, []string{""}, clusterScopedSelectors)

	manyNs := NewIncludeSelector("a,b,c,d,e")
	assert.Equal(t, []string{""}, manyNs.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "clusterroles"}, nil))

	// A value naming no namespace narrows nothing, so it collapses to the single
	// unfiltered query. An empty slice would make pullSingleResource run no query
	// at all and drop the resource without recording a failure.
	emptyNs := NewIncludeSelector("")
	assert.Equal(t, []string{""}, emptyNs.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil))

	// malformed input with empty segments: empty segments are skipped
	malformed := NewIncludeSelector("ns1,,ns3")
	malformedSelectors := malformed.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"}, nil)
	assert.Equal(t, 2, len(malformedSelectors))
	assert.Equal(t, "metadata.namespace==ns1", malformedSelectors[0])
	assert.Equal(t, "metadata.namespace==ns3", malformedSelectors[1])
}

func TestAllowsNamespace(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	podGVR := &schema.GroupVersionResource{Resource: "pods"}
	nodeGVR := &schema.GroupVersionResource{Resource: "nodes"}
	nsGVR := &schema.GroupVersionResource{Resource: "namespaces"}

	trueVal := true
	falseVal := false

	t.Run("empty selector allows everything", func(t *testing.T) {
		es := &EmptySelector{}
		assert.True(t, es.AllowsNamespace(podGVR, "default", nil))
		assert.True(t, es.AllowsNamespace(podGVR, "kube-system", nil))
		assert.True(t, es.AllowsNamespace(nodeGVR, "", nil))
		assert.True(t, es.AllowsNamespace(nsGVR, "default", nil))
	})

	t.Run("exclude selector", func(t *testing.T) {
		es := NewExcludeSelector("dev,staging")
		// excluded namespaces
		assert.False(t, es.AllowsNamespace(podGVR, "dev", nil))
		assert.False(t, es.AllowsNamespace(podGVR, "staging", nil))
		// allowed namespace
		assert.True(t, es.AllowsNamespace(podGVR, "prod", nil))
		assert.True(t, es.AllowsNamespace(podGVR, "default", nil))
		// cluster-scoped resources are allowed
		assert.True(t, es.AllowsNamespace(nodeGVR, "", nil))
		assert.True(t, es.AllowsNamespace(nodeGVR, "dev", &falseVal))
		// namespaces resource checked by name
		assert.False(t, es.AllowsNamespace(nsGVR, "dev", nil))
		assert.True(t, es.AllowsNamespace(nsGVR, "prod", nil))
		// explicit namespaced override
		assert.False(t, es.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "dev", &trueVal))
		assert.True(t, es.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "prod", &trueVal))
		assert.True(t, es.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "dev", &falseVal))

		// empty exclude selector allows everything
		emptyExclude := NewExcludeSelector("")
		assert.True(t, emptyExclude.AllowsNamespace(podGVR, "dev", nil))
	})

	t.Run("include selector", func(t *testing.T) {
		is := NewIncludeSelector("prod,staging")
		// included namespaces
		assert.True(t, is.AllowsNamespace(podGVR, "prod", nil))
		assert.True(t, is.AllowsNamespace(podGVR, "staging", nil))
		// non-included namespaces
		assert.False(t, is.AllowsNamespace(podGVR, "dev", nil))
		assert.False(t, is.AllowsNamespace(podGVR, "default", nil))
		assert.False(t, is.AllowsNamespace(podGVR, "", nil))
		// cluster-scoped resources are allowed
		assert.True(t, is.AllowsNamespace(nodeGVR, "", nil))
		assert.True(t, is.AllowsNamespace(nodeGVR, "dev", &falseVal))
		// namespaces resource checked by name
		assert.True(t, is.AllowsNamespace(nsGVR, "prod", nil))
		assert.False(t, is.AllowsNamespace(nsGVR, "dev", nil))
		// explicit namespaced override
		assert.True(t, is.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "prod", &trueVal))
		assert.False(t, is.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "dev", &trueVal))
		assert.True(t, is.AllowsNamespace(&schema.GroupVersionResource{Resource: "customresources"}, "dev", &falseVal))

		// empty include selector allows everything
		emptyInclude := NewIncludeSelector("")
		assert.True(t, emptyInclude.AllowsNamespace(podGVR, "dev", nil))
	})
}
