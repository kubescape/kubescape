package hostsensorutils

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestNewHostSensorHandlerDoesNotMutateSharedK8sConfig(t *testing.T) {
	sharedConfig := &rest.Config{
		Host: "https://cluster.example.test",
		ContentConfig: rest.ContentConfig{
			AcceptContentTypes: "application/json",
			ContentType:        "application/json",
		},
	}
	originalConfig := k8sinterface.K8SConfig
	k8sinterface.K8SConfig = sharedConfig
	t.Cleanup(func() {
		k8sinterface.K8SConfig = originalConfig
	})

	k8sObj := NewKubernetesApiMock(WithNode(v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}))
	k8sObj.Context = context.Background()

	handler, err := NewHostSensorHandler(k8sObj, "")

	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.Equal(t, "application/json", sharedConfig.AcceptContentTypes)
	assert.Equal(t, "application/json", sharedConfig.ContentType)
}
