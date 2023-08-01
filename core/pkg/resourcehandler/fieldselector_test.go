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
	selectors := es.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"})
	assert.Equal(t, 1, len(selectors))
	assert.Equal(t, "metadata.namespace!=default,metadata.namespace!=ingress", selectors[0])

	selectors2 := es.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "namespaces"})
	assert.Equal(t, 1, len(selectors2))
	assert.Equal(t, "metadata.name!=default,metadata.name!=ingress", selectors2[0])
}

func TestIncludeNamespacesSelectors(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	is := NewIncludeSelector("default,ingress")
	selectors := is.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "pods"})
	assert.Equal(t, 2, len(selectors))
	assert.Equal(t, "metadata.namespace==default", selectors[0])
	assert.Equal(t, "metadata.namespace==ingress", selectors[1])

	selectors2 := is.GetNamespacesSelectors(&schema.GroupVersionResource{Resource: "namespaces"})
	assert.Equal(t, 2, len(selectors2))
	assert.Equal(t, "metadata.name==default", selectors2[0])
	assert.Equal(t, "metadata.name==ingress", selectors2[1])
}
