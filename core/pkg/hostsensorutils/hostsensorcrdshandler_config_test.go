package hostsensorutils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

	handler, err := NewHostSensorHandler(context.Background(), k8sObj, "")

	require.NoError(t, err)
	require.NotNil(t, handler)
	assert.Equal(t, "application/json", sharedConfig.AcceptContentTypes)
	assert.Equal(t, "application/json", sharedConfig.ContentType)
}

// TestNewHostSensorHandlerUsesTheScanContext pins that a stopped scan does not list nodes through the client's own background context.
func TestNewHostSensorHandlerUsesTheScanContext(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"NodeList","apiVersion":"v1","items":[]}`))
	}))
	t.Cleanup(server.Close)

	config := &rest.Config{Host: server.URL}
	originalConfig := k8sinterface.K8SConfig
	k8sinterface.K8SConfig = config
	t.Cleanup(func() { k8sinterface.K8SConfig = originalConfig })
	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	k8sObj := &k8sinterface.KubernetesApi{KubernetesClient: clientset, Context: context.Background()}

	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewHostSensorHandler(stopped, k8sObj, "")

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, requests.Load(), "the node list must not be sent once the scan has stopped")
}
