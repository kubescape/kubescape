package resourcehandler

import (
	"testing"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestGetNamespacesSelector(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	assert.Equal(t, "metadata.namespace==default,", getNamespacesSelector(&schema.GroupVersionResource{Version: "v1", Resource: "pods"}, "default,", "=="))
	assert.Equal(t, "", getNamespacesSelector(&schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, "default,", "=="))
}
