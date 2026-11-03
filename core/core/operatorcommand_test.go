package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

// newFakeOperatorCommandClient returns a fake dynamic client that knows the
// OperatorCommand list kind and, like the API server, turns generateName into
// a unique name on create (the fake object tracker does not do that itself).
func newFakeOperatorCommandClient(t *testing.T) *dynamicfake.FakeDynamicClient {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{operatorCommandGVR: "OperatorCommandList"})
	var counter int64
	dyn.PrependReactor("create", "operatorcommands", func(action clienttesting.Action) (bool, runtime.Object, error) {
		obj := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
		if obj.GetName() == "" && obj.GetGenerateName() != "" {
			obj.SetName(fmt.Sprintf("%s%d", obj.GetGenerateName(), atomic.AddInt64(&counter, 1)))
		}
		return false, nil, nil
	})
	return dyn
}

func setOperatorCommandStatus(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name string, status map[string]interface{}) {
	t.Helper()
	obj, err := dyn.Resource(operatorCommandGVR).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, unstructured.SetNestedField(obj.Object, status, "status"))
	_, err = dyn.Resource(operatorCommandGVR).Namespace(ns).Update(context.Background(), obj, metav1.UpdateOptions{})
	require.NoError(t, err)
}

func TestCreateOperatorCommands_ShapeMatchesScheduler(t *testing.T) {
	dyn := newFakeOperatorCommandClient(t)
	cmds := apis.Commands{Commands: []apis.Command{
		{CommandName: apis.TypeRunKubescape, JobTracking: apis.JobTracking{JobID: "job-123"}},
		{CommandName: apis.TypeScanImages},
	}}

	names, err := CreateOperatorCommands(context.Background(), dyn, "kubescape", cmds)
	require.NoError(t, err)
	require.Len(t, names, 2)
	assert.NotEqual(t, names[0], names[1])

	for i, name := range names {
		obj, err := dyn.Resource(operatorCommandGVR).Namespace("kubescape").Get(context.Background(), name, metav1.GetOptions{})
		require.NoError(t, err)

		assert.Equal(t, "kubescape.io/v1alpha1", obj.GetAPIVersion())
		assert.Equal(t, "OperatorCommand", obj.GetKind())
		assert.Equal(t, "kubescape", obj.GetNamespace())
		assert.Equal(t, "kubescape-cli-", obj.GetGenerateName())
		assert.Equal(t, map[string]string{"kubescape.io/app-name": "operator"}, obj.GetLabels())

		commandType, _, _ := unstructured.NestedString(obj.Object, "spec", "commandType")
		assert.Equal(t, "OperatorAPI", commandType)

		guid, _, _ := unstructured.NestedString(obj.Object, "spec", "guid")
		if i == 0 {
			assert.Equal(t, "job-123", guid, "jobTracking.jobID must become spec.guid")
		} else {
			assert.NotEmpty(t, guid, "a missing jobID must be replaced by a generated UUID")
			assert.Len(t, guid, 36)
		}

		body, _, _ := unstructured.NestedString(obj.Object, "spec", "body")
		raw, err := base64.StdEncoding.DecodeString(body)
		require.NoError(t, err, "spec.body must be base64")
		wantJSON, err := json.Marshal(cmds.Commands[i])
		require.NoError(t, err)
		assert.JSONEq(t, string(wantJSON), string(raw))
	}
}

func TestWaitForOperatorCommands_CompletesOnStatus(t *testing.T) {
	dyn := newFakeOperatorCommandClient(t)
	names, err := CreateOperatorCommands(context.Background(), dyn, "kubescape",
		apis.Commands{Commands: []apis.Command{{CommandName: apis.TypeRunKubescape}, {CommandName: apis.TypeScanImages}}})
	require.NoError(t, err)
	for _, n := range names {
		setOperatorCommandStatus(t, dyn, "kubescape", n, map[string]interface{}{"started": true, "completed": true})
	}

	require.NoError(t, WaitForOperatorCommands(context.Background(), dyn, "kubescape", names, 5*time.Second))
}

func TestWaitForOperatorCommands_ReportsError(t *testing.T) {
	dyn := newFakeOperatorCommandClient(t)
	names, err := CreateOperatorCommands(context.Background(), dyn, "kubescape",
		apis.Commands{Commands: []apis.Command{{CommandName: apis.TypeRunKubescape}}})
	require.NoError(t, err)
	setOperatorCommandStatus(t, dyn, "kubescape", names[0], map[string]interface{}{
		"started": true,
		"error":   map[string]interface{}{"reason": "Failed", "message": "scan blew up"},
	})

	err = WaitForOperatorCommands(context.Background(), dyn, "kubescape", names, 5*time.Second)
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("operator command %s failed: scan blew up", names[0]), err.Error())
}

func TestWaitForOperatorCommands_Timeout(t *testing.T) {
	dyn := newFakeOperatorCommandClient(t)
	names, err := CreateOperatorCommands(context.Background(), dyn, "kubescape",
		apis.Commands{Commands: []apis.Command{{CommandName: apis.TypeRunKubescape}}})
	require.NoError(t, err)

	err = WaitForOperatorCommands(context.Background(), dyn, "kubescape", names, 100*time.Millisecond)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "timed out after 100ms waiting for operator commands"), err.Error())
}
