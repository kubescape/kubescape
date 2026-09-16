package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
)

func writeLifecycleKubeconfig(t *testing.T, contexts ...string) string {
	t.Helper()
	require.NotEmpty(t, contexts)

	path := filepath.Join(t.TempDir(), "config")
	content := "apiVersion: v1\nkind: Config\nclusters:\n"
	for _, name := range contexts {
		content += fmt.Sprintf("- name: %s\n  cluster:\n    server: https://%s.invalid\n", name, name)
	}
	content += "contexts:\n"
	for _, name := range contexts {
		content += fmt.Sprintf("- name: %s\n  context:\n    cluster: %s\n    user: %s\n", name, name, name)
	}
	content += "users:\n"
	for _, name := range contexts {
		content += fmt.Sprintf("- name: %s\n  user:\n    token: %s-token\n", name, name)
	}
	content += "current-context: " + contexts[0] + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func installLifecycleKubeconfig(t *testing.T, contexts ...string) {
	t.Helper()
	path := writeLifecycleKubeconfig(t, contexts...)
	t.Setenv("KUBECONFIG", path)

	previous := k8sinterface.GetContextName()
	k8sinterface.SetClusterContextName(contexts[0])
	t.Cleanup(func() {
		k8sinterface.SetClusterContextName(previous)
	})
}

func lifecycleScanInfo(t *testing.T, contextName string) *cautils.ScanInfo {
	t.Helper()
	info := &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster}
	info.SetKubeconfigSelection(os.Getenv("KUBECONFIG"), contextName)
	require.NoError(t, info.ResolveClusterContextName())
	return info
}

func lifecycleKubescape() meta.IKubescape {
	return &fleetOutcomeKubescape{}
}

type lifecycleContextKubescape struct {
	meta.IKubescape
	ctx context.Context
}

func (k *lifecycleContextKubescape) Context() context.Context {
	return k.ctx
}

func (k *lifecycleContextKubescape) SetContext(ctx context.Context) {
	k.ctx = ctx
}

func TestRunFleetContext_RestoresAmbientContextOnEveryReturn(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	tests := []struct {
		name   string
		result *resultshandling.ResultsHandler
		runErr error
	}{
		{name: "successful scan"},
		{name: "runner error", runErr: errors.New("policy download failed")},
		{
			name:   "result returned with threshold error",
			result: &resultshandling.ResultsHandler{},
			runErr: errors.New("compliance threshold failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sinterface.SetClusterContextName("ambient")
			var selectedInside string
			run := func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				selectedInside = k8sinterface.GetContextName()
				return tt.result, tt.runErr
			}

			got, err, elapsed := runFleetContext("target", lifecycleScanInfo(t, "target"), lifecycleKubescape(), nil, run)

			assert.Equal(t, "target", selectedInside)
			assert.Equal(t, "ambient", k8sinterface.GetContextName())
			assert.Same(t, tt.result, got)
			assert.ErrorIs(t, err, tt.runErr)
			assert.GreaterOrEqual(t, elapsed, time.Duration(0))
		})
	}
}

func TestRunFleetContext_CancelsDerivedContextOnEveryReturn(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	tests := []struct {
		name   string
		runErr error
	}{
		{name: "success"},
		{name: "error", runErr: errors.New("scan failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var runnerContext context.Context
			info := lifecycleScanInfo(t, "target")
			info.ScanTimeout = time.Minute
			run := func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				runnerContext = ctx
				select {
				case <-ctx.Done():
					t.Fatal("derived context was cancelled before the runner returned")
				default:
				}
				return nil, tt.runErr
			}

			_, _, _ = runFleetContext("target", info, lifecycleKubescape(), nil, run)
			require.NotNil(t, runnerContext)
			select {
			case <-runnerContext.Done():
				assert.ErrorIs(t, runnerContext.Err(), context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("derived context was not cancelled after the runner returned")
			}
		})
	}
}

func TestRunFleetContext_PanicRestoresContextAndCancelsRequest(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	var runnerContext context.Context
	var selectedInside string
	panicValue := errors.New("runner panic")
	info := lifecycleScanInfo(t, "target")
	info.ScanTimeout = time.Minute

	func() {
		defer func() {
			assert.Same(t, panicValue, recover())
		}()
		_, _, _ = runFleetContext("target", info, lifecycleKubescape(), nil,
			func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				runnerContext = ctx
				selectedInside = k8sinterface.GetContextName()
				panic(panicValue)
			})
	}()

	assert.Equal(t, "target", selectedInside)
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
	require.NotNil(t, runnerContext)
	select {
	case <-runnerContext.Done():
		assert.ErrorIs(t, runnerContext.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("panic path leaked the derived scan context")
	}
}

func TestFleetScan_PanicDoesNotPoisonTheNextScanContext(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "broken", "healthy")

	base := cautils.ScanInfo{
		KubeContexts: []string{"broken"},
		ScanType:     cautils.ScanTypeCluster,
		Output:       filepath.Join(t.TempDir(), "report.json"),
	}
	panicValue := "simulated scanner panic"

	func() {
		defer func() {
			assert.Equal(t, panicValue, recover())
		}()
		_ = fleetScan(base, lifecycleKubescape(), nil,
			func(_ context.Context, info *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				assert.Equal(t, "broken", info.GetClusterContextName())
				assert.Equal(t, "broken", k8sinterface.GetContextName())
				panic(panicValue)
			})
	}()

	assert.Equal(t, "ambient", k8sinterface.GetContextName())

	var selectedInside string
	next := base
	next.KubeContexts = []string{"healthy"}
	err := fleetScan(next, lifecycleKubescape(), nil,
		func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			selectedInside = k8sinterface.GetContextName()
			return nil, nil
		})
	require.NoError(t, err)
	assert.Equal(t, "healthy", selectedInside)
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_RestoresImmediateCallerInNestedUse(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "outer", "inner")

	outerLeave := cautils.EnterClusterContext("outer")
	require.Equal(t, "outer", k8sinterface.GetContextName())

	_, _, _ = runFleetContext("inner", lifecycleScanInfo(t, "inner"), lifecycleKubescape(), nil,
		func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			assert.Equal(t, "inner", k8sinterface.GetContextName())
			return nil, nil
		})

	assert.Equal(t, "outer", k8sinterface.GetContextName())
	outerLeave()
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_PreservesRunnerOutputs(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	wantResults := &resultshandling.ResultsHandler{}
	wantErr := errors.New("threshold failed")
	policies := []cautils.PolicyIdentifier{{Kind: "framework", Identifier: "nsa"}}
	result, err, elapsed := runFleetContext("target", lifecycleScanInfo(t, "target"), lifecycleKubescape(), policies,
		func(_ context.Context, info *cautils.ScanInfo, _ meta.IKubescape, gotPolicies []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			assert.Equal(t, "target", info.GetClusterContextName())
			assert.Equal(t, policies, gotPolicies)
			return wantResults, wantErr
		},
	)

	assert.Same(t, wantResults, result)
	assert.ErrorIs(t, err, wantErr)
	assert.GreaterOrEqual(t, elapsed, time.Duration(0))
}

func TestRunFleetContext_MeasuresRunnerDuration(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("timers are not precise enough under wasm")
	}
	installLifecycleKubeconfig(t, "ambient", "target")

	const work = 20 * time.Millisecond
	_, _, elapsed := runFleetContext("target", lifecycleScanInfo(t, "target"), lifecycleKubescape(), nil,
		func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			time.Sleep(work)
			return nil, nil
		})

	assert.GreaterOrEqual(t, elapsed, work)
	assert.Less(t, elapsed, time.Second)
}

func TestRunFleetContext_HonorsPerClusterTimeoutAndRestoresContext(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "slow")

	info := lifecycleScanInfo(t, "slow")
	info.ScanTimeout = 25 * time.Millisecond
	ks := &lifecycleContextKubescape{ctx: context.Background()}
	var runnerContext context.Context

	result, err, elapsed := runFleetContext("slow", info, ks, nil,
		func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			runnerContext = ctx
			assert.Equal(t, "slow", k8sinterface.GetContextName())
			<-ctx.Done()
			return nil, ctx.Err()
		})

	assert.Nil(t, result)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.GreaterOrEqual(t, elapsed, 25*time.Millisecond)
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
	require.NotNil(t, runnerContext)
	assert.ErrorIs(t, runnerContext.Err(), context.DeadlineExceeded)
}

func TestRunFleetContext_PropagatesCancelledParentContext(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ks := &lifecycleContextKubescape{ctx: parent}
	info := lifecycleScanInfo(t, "target")
	info.ScanTimeout = time.Minute

	_, err, _ := runFleetContext("target", info, ks, nil,
		func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			assert.Equal(t, "target", k8sinterface.GetContextName())
			assert.ErrorIs(t, ctx.Err(), context.Canceled)
			return nil, ctx.Err()
		})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_TimeoutContextIsCancelledAfterFastSuccess(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	info := lifecycleScanInfo(t, "target")
	info.ScanTimeout = time.Minute
	ks := &lifecycleContextKubescape{ctx: context.Background()}
	var runnerContext context.Context

	_, err, _ := runFleetContext("target", info, ks, nil,
		func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			runnerContext = ctx
			assert.NoError(t, ctx.Err())
			return nil, nil
		})
	require.NoError(t, err)

	require.NotNil(t, runnerContext)
	select {
	case <-runnerContext.Done():
		assert.ErrorIs(t, runnerContext.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("successful fast scan leaked its timeout timer and context")
	}
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_PanicWithTimeoutRunsBothCleanups(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	info := lifecycleScanInfo(t, "target")
	info.ScanTimeout = time.Minute
	ks := &lifecycleContextKubescape{ctx: context.Background()}
	var runnerContext context.Context
	panicValue := struct{ reason string }{reason: "unexpected scanner state"}

	func() {
		defer func() {
			assert.Equal(t, panicValue, recover())
		}()
		_, _, _ = runFleetContext("target", info, ks, nil,
			func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				runnerContext = ctx
				panic(panicValue)
			})
	}()

	assert.Equal(t, "ambient", k8sinterface.GetContextName())
	require.NotNil(t, runnerContext)
	select {
	case <-runnerContext.Done():
		assert.ErrorIs(t, runnerContext.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("panic leaked the timeout context")
	}
}

func TestRunFleetContext_SequentialCallsDoNotLeakContextBetweenClusters(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "prod", "staging", "dr")

	ks := lifecycleKubescape()
	observed := make([]string, 0, 3)
	for _, name := range []string{"prod", "staging", "dr"} {
		info := lifecycleScanInfo(t, name)
		_, err, _ := runFleetContext(name, info, ks, nil,
			func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				observed = append(observed, k8sinterface.GetContextName())
				return nil, nil
			})
		require.NoError(t, err)
		assert.Equal(t, "ambient", k8sinterface.GetContextName(), "each context must be restored before the next iteration")
	}

	assert.Equal(t, []string{"prod", "staging", "dr"}, observed)
}

func TestRunFleetContext_PassesExactInputsToRunner(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	info := lifecycleScanInfo(t, "target")
	ks := lifecycleKubescape()
	policies := []cautils.PolicyIdentifier{
		{Kind: "framework", Identifier: "nsa"},
		{Kind: "control", Identifier: "C-0016"},
	}
	called := false

	_, err, _ := runFleetContext("target", info, ks, policies,
		func(_ context.Context, gotInfo *cautils.ScanInfo, gotKS meta.IKubescape, gotPolicies []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			called = true
			assert.Same(t, info, gotInfo)
			assert.Same(t, ks, gotKS)
			assert.Equal(t, policies, gotPolicies)
			return nil, nil
		})

	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_ErrorIdentitySurvivesCleanup(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	sentinel := errors.New("sentinel runner failure")
	_, err, _ := runFleetContext("target", lifecycleScanInfo(t, "target"), lifecycleKubescape(), nil,
		func(_ context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			return nil, fmt.Errorf("scan target: %w", sentinel)
		})

	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, "scan target: sentinel runner failure", err.Error())
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestRunFleetContext_NoTimeoutDoesNotCancelSharedParent(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "target")

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ks := &lifecycleContextKubescape{ctx: parent}
	info := lifecycleScanInfo(t, "target")
	info.ScanTimeout = 0
	var observed context.Context

	_, err, _ := runFleetContext("target", info, ks, nil,
		func(ctx context.Context, _ *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			observed = ctx
			return nil, nil
		})

	require.NoError(t, err)
	assert.Equal(t, parent, observed, "without a timeout the runner must receive the Kubescape parent context directly")
	assert.NoError(t, parent.Err(), "the no-op cleanup must not cancel a context owned by the caller")
	assert.Equal(t, "ambient", k8sinterface.GetContextName())
}

func TestFleetScan_PanicRestoresContextBeforeUnwindingPastRemainingClusters(t *testing.T) {
	installLifecycleKubeconfig(t, "ambient", "first", "panics", "never-runs")

	info := cautils.ScanInfo{
		KubeContexts: []string{"first", "panics", "never-runs"},
		ScanType:     cautils.ScanTypeCluster,
		Output:       filepath.Join(t.TempDir(), "report.json"),
	}
	visited := make([]string, 0, 3)
	panicValue := errors.New("fatal scanner invariant")

	func() {
		defer func() {
			assert.Equal(t, panicValue, recover())
		}()
		_ = fleetScan(info, lifecycleKubescape(), nil,
			func(_ context.Context, scanInfo *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
				active := k8sinterface.GetContextName()
				visited = append(visited, active)
				assert.Equal(t, scanInfo.GetClusterContextName(), active)
				if active == "panics" {
					panic(panicValue)
				}
				return nil, nil
			})
	}()

	assert.Equal(t, []string{"first", "panics"}, visited, "panic propagation must retain existing fail-fast behavior")
	assert.Equal(t, "ambient", k8sinterface.GetContextName(), "cleanup must run before the panic reaches an outer recovery boundary")
}
