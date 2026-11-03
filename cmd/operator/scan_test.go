package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestGetOperatorScanCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanCmd(mockKubescape, &operatorInfo)

	assert.Equal(t, "scan", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "for operator scan sub command, you must pass at least 1 more sub commands, see above examples"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"operator"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{})
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{"configurations"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{"vulnerabilities"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{"random"})
	expectedErrorMessage = "for the operator sub-command, only " + vulnerabilitiesSubCommand + " and " + configurationsSubCommand + " are supported. Refer to the examples above"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

// TestOperatorScanCmd_NamespaceFlagPropagatesToChildCommands guards against a
// regression where operatorInfo was passed by value into the "configurations"
// and "vulnerabilities" child commands: the child received a copy frozen at
// the flag's default value, so a user-supplied --namespace was silently
// ignored by the command that actually reads it.
//
// It substitutes newOperatorAdapter instead of calling into core.NewOperatorAdapter,
// both to avoid touching a real cluster (which can hang or os.Exit via
// logger.L().Fatal on an unusable kubeconfig) and to assert on the exact
// (scanInfo, namespace) pair the child hands to it — the parent's
// operatorInfo.Namespace alone doesn't prove the child read it.
func TestOperatorScanCmd_NamespaceFlagPropagatesToChildCommands(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := &cautils.OperatorInfo{}

	var gotScanInfo cautils.OperatorScanInfo
	var gotNamespace string
	var gotCtx context.Context
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, ns string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		gotScanInfo = scanInfo
		gotNamespace = ns
		if len(ctx) > 0 {
			gotCtx = ctx[0]
		}
		return nil, errors.New("stub: no real cluster in unit tests")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(mockKubescape, operatorInfo)
	cmd.SetArgs([]string{"configurations", "--namespace", "custom-ns"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.Error(t, err) // the stub always errors; we only care what it was called with

	assert.Equal(t, "custom-ns", operatorInfo.Namespace)
	assert.Equal(t, "custom-ns", gotNamespace)
	assert.IsType(t, &cautils.ConfigScanInfo{}, gotScanInfo)
	assert.NotNil(t, gotCtx, "constructor must receive command context")
}

// TestOperatorScanConfigCmd_FrameworksDefaultsToAll guards the flag-level
// default: with no --frameworks passed, the scan info received by the operator
// adapter must carry ["all"], not an empty slice. The default lives at the
// flag boundary (cmd/operator/configscan.go), not inside GetRequestPayload.
func TestOperatorScanConfigCmd_FrameworksDefaultsToAll(t *testing.T) {
	var gotScanInfo cautils.OperatorScanInfo
	prev := newOperatorAdapter
	newOperatorAdapter = func(si cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		gotScanInfo = si
		return nil, errors.New("stub")
	}
	t.Cleanup(func() { newOperatorAdapter = prev })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	_ = cmd.Execute()

	cfg, ok := gotScanInfo.(*cautils.ConfigScanInfo)
	require.True(t, ok)
	assert.Equal(t, []string{"all"}, cfg.Frameworks)
}

// TestOperatorScanConfigCmd_ExplicitFrameworksReplacesDefault guards pflag's
// replace-on-first-set semantics: an explicit --frameworks value must replace
// the ["all"] default, not append to it (pflag v1.0.10 string_slice.go Set()).
func TestOperatorScanConfigCmd_ExplicitFrameworksReplacesDefault(t *testing.T) {
	var gotScanInfo cautils.OperatorScanInfo
	prev := newOperatorAdapter
	newOperatorAdapter = func(si cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		gotScanInfo = si
		return nil, errors.New("stub")
	}
	t.Cleanup(func() { newOperatorAdapter = prev })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations", "--frameworks", "nsa,mitre"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	_ = cmd.Execute()

	cfg, ok := gotScanInfo.(*cautils.ConfigScanInfo)
	require.True(t, ok)
	assert.Equal(t, []string{"nsa", "mitre"}, cfg.Frameworks)
}

func TestOperatorScanConfigCmd_ContextCanceled(t *testing.T) {
	var capturedCtx context.Context
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		if len(ctx) > 0 {
			capturedCtx = ctx[0]
		}
		if capturedCtx != nil && capturedCtx.Err() != nil {
			return nil, capturedCtx.Err()
		}
		return nil, errors.New("unexpected call")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ctx, capturedCtx, "constructor must receive the command context")
}

func TestOperatorScanConfigCmd_ContextCanceled_NoCommandsCreated(t *testing.T) {
	op := newFakeOperator(t, "")
	op.install(t)

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, op.created(t), "must not create operator commands when context is canceled")
}

// fakeOperator stands in for the Kubescape Operator: it serves the OperatorCommand
// resource from a fake dynamic client, completes each command as it is created (or
// fails it with failMessage) and records what the CLI created.
type fakeOperator struct {
	dyn *dynamicfake.FakeDynamicClient
}

func newFakeOperator(t *testing.T, failMessage string) *fakeOperator {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "kubescape.io", Version: "v1alpha1", Resource: "operatorcommands"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: "OperatorCommandList"})
	var counter int64
	dyn.PrependReactor("create", "operatorcommands", func(action clienttesting.Action) (bool, runtime.Object, error) {
		obj := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
		obj.SetName(fmt.Sprintf("%s%d", obj.GetGenerateName(), atomic.AddInt64(&counter, 1)))
		status := map[string]interface{}{"started": true, "completed": true}
		if failMessage != "" {
			status = map[string]interface{}{"started": true, "error": map[string]interface{}{"reason": "Failed", "message": failMessage}}
		}
		_ = unstructured.SetNestedField(obj.Object, status, "status")
		return false, nil, nil
	})
	return &fakeOperator{dyn: dyn}
}

// install makes the commands under test talk to this fake operator.
func (f *fakeOperator) install(t *testing.T) {
	t.Helper()
	prev := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, ns string, _ ...context.Context) (*core.OperatorAdapter, error) {
		return core.NewOperatorAdapterWithClient(scanInfo, ns, f.dyn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prev })
}

// created returns the OperatorCommand objects created so far.
func (f *fakeOperator) created(t *testing.T) []unstructured.Unstructured {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "kubescape.io", Version: "v1alpha1", Resource: "operatorcommands"}
	list, err := f.dyn.Resource(gvr).Namespace(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	return list.Items
}

// commands decodes the apis.Command carried in spec.body of each created object.
func (f *fakeOperator) commands(t *testing.T) []apis.Command {
	t.Helper()
	var cmds []apis.Command
	for _, obj := range f.created(t) {
		body, _, _ := unstructured.NestedString(obj.Object, "spec", "body")
		raw, err := base64.StdEncoding.DecodeString(body)
		require.NoError(t, err)
		var cmd apis.Command
		require.NoError(t, json.Unmarshal(raw, &cmd))
		cmds = append(cmds, cmd)
	}
	return cmds
}
