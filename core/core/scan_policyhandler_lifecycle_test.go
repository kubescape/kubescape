package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/require"
)

type blockingPolicyGetter struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

var policyHandlerLifecycleTestID atomic.Uint64

func (g *blockingPolicyGetter) GetFramework(string) (*reporthandling.Framework, error) {
	if g.calls.Add(1) == 1 {
		close(g.started)
		<-g.release
	}
	return mocks.MockFramework_0006_0013(), nil
}

func (g *blockingPolicyGetter) GetFrameworks() ([]reporthandling.Framework, error) {
	return nil, nil
}

func (g *blockingPolicyGetter) GetControl(string) (*reporthandling.Control, error) {
	return nil, nil
}

func (g *blockingPolicyGetter) ListFrameworks() ([]string, error) { return nil, nil }

func (g *blockingPolicyGetter) ListControls() ([]string, error) { return nil, nil }

type emptyExceptionsGetter struct{}

func (emptyExceptionsGetter) GetExceptions(context.Context, string) ([]armotypes.PostureExceptionPolicy, error) {
	return nil, nil
}

type emptyControlInputsGetter struct{}

func (emptyControlInputsGetter) GetControlsInputs(context.Context, string) (map[string][]string, error) {
	return map[string][]string{"test-control": {"test-value"}}, nil
}

// TestCollectPoliciesKeepsSharedHandlerAliveUntilReturn reproduces the lifecycle
// race from the production scan path. A policy download stays in flight past
// the registry idle window while another access triggers a sweep. The
// completed download must remain cached on the original handler.
func TestCollectPoliciesKeepsSharedHandlerAliveUntilReturn(t *testing.T) {
	t.Setenv(policyhandler.PoliciesCacheTtlEnvVar, "100ms")

	oldStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = oldStore })

	policyGetter := &blockingPolicyGetter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	getters := &cautils.Getters{
		PolicyGetter:         policyGetter,
		ExceptionsGetter:     emptyExceptionsGetter{},
		ControlsInputsGetter: emptyControlInputsGetter{},
	}
	identifiers := []cautils.PolicyIdentifier{{Identifier: "framework-0006-0013", Kind: "Framework"}}
	scanInfo := &cautils.ScanInfo{}
	testID := policyHandlerLifecycleTestID.Add(1)
	clusterName := fmt.Sprintf("%s-active-%d", t.Name(), testID)

	done := make(chan error, 1)
	go func() {
		_, err := collectPolicies(context.Background(), clusterName, identifiers, scanInfo, getters)
		done <- err
	}()

	select {
	case <-policyGetter.started:
	case <-time.After(5 * time.Second):
		t.Fatal("policy getter did not start")
	}

	// Make the registry entry old enough for the next access to sweep it while
	// the policy getter is still in flight unless collection owns a reference.
	time.Sleep(200 * time.Millisecond)
	policyhandler.NewPolicyHandler(clusterName)
	close(policyGetter.release)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("policy collection did not finish")
	}

	_, err := collectPolicies(context.Background(), clusterName, identifiers, scanInfo, getters)
	require.NoError(t, err)
	require.Equal(t, int32(1), policyGetter.calls.Load(), "the completed download should remain cached on the same live handler")
}
