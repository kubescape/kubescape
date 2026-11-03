package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
)

func TestNewOperatorAdapter_NotConnectedToCluster(t *testing.T) {
	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(false)

	adapter, err := NewOperatorAdapter(&fakeOperatorScanInfo{}, "kubescape")

	assert.Nil(t, adapter)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not connect to cluster")
}

// fakeOperatorScanInfo lets OperatorScan be driven directly, without a real cluster.
type fakeOperatorScanInfo struct {
	payload       *apis.Commands
	validateErr   error
	validateCalls int
}

func (f *fakeOperatorScanInfo) GetRequestPayload() *apis.Commands {
	if f.payload != nil {
		return f.payload
	}
	return &apis.Commands{Commands: []apis.Command{{CommandName: "scan"}}}
}

func (f *fakeOperatorScanInfo) ValidatePayload(*apis.Commands) error {
	f.validateCalls++
	return f.validateErr
}

var _ cautils.OperatorScanInfo = (*fakeOperatorScanInfo)(nil)

func TestOperatorAdapter_OperatorScan(t *testing.T) {
	t.Run("invalid payload short-circuits before any cluster call", func(t *testing.T) {
		dyn := newFakeOperatorCommandClient(t)
		scanInfo := &fakeOperatorScanInfo{validateErr: errors.New("missing target namespace")}
		adapter := NewOperatorAdapterWithClient(scanInfo, "kubescape", dyn)

		got, err := adapter.OperatorScan()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing target namespace")
		assert.Empty(t, got)
		assert.Equal(t, 1, scanInfo.validateCalls)
		assert.Empty(t, dyn.Actions(), "must not touch the cluster when the payload is invalid")
	})

	t.Run("valid payload creates the commands and waits for completion", func(t *testing.T) {
		dyn := newFakeOperatorCommandClient(t)
		// The operator is not running in this test: complete each command as it is created.
		dyn.PrependReactor("create", "operatorcommands", func(action clienttesting.Action) (bool, runtime.Object, error) {
			obj := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
			_ = unstructured.SetNestedField(obj.Object, map[string]interface{}{"started": true, "completed": true}, "status")
			return false, nil, nil
		})
		payload := &apis.Commands{Commands: []apis.Command{{CommandName: "scan", ResponseID: "distinctive-marker-2f7b1d"}}}
		adapter := NewOperatorAdapterWithClient(&fakeOperatorScanInfo{payload: payload}, "kubescape", dyn)

		got, err := adapter.OperatorScan()

		require.NoError(t, err)
		assert.Equal(t, "success", got)
		list, err := dyn.Resource(operatorCommandGVR).Namespace("kubescape").List(context.Background(), metav1.ListOptions{})
		require.NoError(t, err)
		assert.Len(t, list.Items, 1)
	})

	t.Run("failed command is reported", func(t *testing.T) {
		dyn := newFakeOperatorCommandClient(t)
		dyn.PrependReactor("create", "operatorcommands", func(action clienttesting.Action) (bool, runtime.Object, error) {
			obj := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
			_ = unstructured.SetNestedField(obj.Object, map[string]interface{}{"error": map[string]interface{}{"message": "boom"}}, "status")
			return false, nil, nil
		})
		adapter := NewOperatorAdapterWithClient(&fakeOperatorScanInfo{}, "kubescape", dyn)

		got, err := adapter.OperatorScan()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed: boom")
		assert.Empty(t, got)
	})

	t.Run("times out when the operator never completes the command", func(t *testing.T) {
		dyn := newFakeOperatorCommandClient(t)
		adapter := NewOperatorAdapterWithClient(&fakeOperatorScanInfo{}, "kubescape", dyn)
		adapter.timeout = 50 * time.Millisecond

		_, err := adapter.OperatorScan()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out after 50ms waiting for operator commands")
	})

	t.Run("returns early on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dyn := newFakeOperatorCommandClient(t)
		adapter := NewOperatorAdapterWithClient(&fakeOperatorScanInfo{payload: &apis.Commands{}}, "kubescape", dyn)

		got, err := adapter.OperatorScan(ctx)

		require.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, got)
		assert.Empty(t, dyn.Actions(), "must not create commands when the context is cancelled")
	})
}
