package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// These tests reuse the harness from analysis_coalescing_test.go: every API
// request is counted and can be parked, and calls go through the registered
// MCP handler. Both registered names run one shared handler, so every
// scenario is exercised through each name.

var secretToolNames = []string{"detect_secret_exposure", "analyze_secret_exposure"}

func newSecretCoalescingHarness(t *testing.T) *analysisHarness {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		deploymentGVR: "DeploymentList", daemonSetGVR: "DaemonSetList", statefulSetGVR: "StatefulSetList",
		replicaSetGVR: "ReplicaSetList", jobGVR: "JobList", cronJobGVR: "CronJobList",
		podGVR: "PodList", configMapGVR: "ConfigMapList",
	}
	objs := []runtime.Object{
		testSecretConfigMap("prod", "app-config", map[string]string{"db": testDatabaseURL()}),
		testSecretDeployment("prod", "web", []map[string]any{{
			"name": "c", "image": "i",
			"env": []any{map[string]any{"name": "PASSWORD", "value": testPassword()}},
		}}),
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)

	h := &analysisHarness{counter: &apiCounter{}, gate: &apiGate{}}
	h.counter.hook = h.gate.hook
	h.server = &KubescapeMcpserver{
		s:         server.NewMCPServer("kubescape-test", "test", server.WithToolCapabilities(false), server.WithRecovery()),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: countingDynamic{dyn, h.counter}},
	}
	createSecretExposureTools(h.server)
	t.Cleanup(h.gate.open)
	return h
}

var secretBase = map[string]any{"namespace": "prod"}

// secretSingleCall returns one invocation's API-call count and response text
// on a fresh harness; coalesced runs are compared against it.
func secretSingleCall(t *testing.T, tool string, args map[string]any) (int64, string) {
	t.Helper()
	h := newSecretCoalescingHarness(t)
	res, err := invokeTool(context.Background(), h.server, tool, args)
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(t, res))
	return h.counter.total(), resultText(t, res)
}

func TestSecretExposureCoalescing_ScanFindsSomething(t *testing.T) {
	// Guard: the fixtures must actually produce findings, otherwise the
	// equivalence checks below would compare empty results.
	_, text := secretSingleCall(t, secretToolNames[0], secretBase)
	var parsed SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(text), &parsed))
	require.Positive(t, parsed.FindingsCount)
}

func TestSecretExposureCoalescing_IdenticalRequestsShareOneExecution(t *testing.T) {
	const callers = 12
	for _, tool := range secretToolNames {
		t.Run(tool, func(t *testing.T) {
			perCall, want := secretSingleCall(t, tool, secretBase)
			require.Positive(t, perCall)

			h := newSecretCoalescingHarness(t)
			h.gate.arm()
			calls := []<-chan callOutcome{startCall(context.Background(), h.server, tool, secretBase)}
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			for i := 1; i < callers; i++ {
				calls = append(calls, startCall(context.Background(), h.server, tool, secretBase))
			}
			waitForCallers(t, h, 1, callers)
			require.EqualValues(t, 1, h.gate.blocked.Load())
			h.gate.open()

			seen := map[*mcp.CallToolResult]struct{}{}
			for _, c := range calls {
				res := awaitCall(t, c)
				require.False(t, res.IsError)
				require.JSONEq(t, want, resultText(t, res))
				structured, ok := res.StructuredContent.(SecretExposureResult)
				require.True(t, ok, "structured content must keep its concrete type, got %T", res.StructuredContent)
				encoded, err := json.Marshal(structured)
				require.NoError(t, err)
				require.JSONEq(t, want, string(encoded))
				seen[res] = struct{}{}
			}
			require.Len(t, seen, callers)
			require.Equal(t, perCall, h.counter.total(), "%d callers must cost one execution's API calls", callers)
		})
	}
}

func TestSecretExposureCoalescing_BothNamesShareOneExecution(t *testing.T) {
	perCall, want := secretSingleCall(t, secretToolNames[0], secretBase)

	h := newSecretCoalescingHarness(t)
	h.gate.arm()
	var calls []<-chan callOutcome
	calls = append(calls, startCall(context.Background(), h.server, "detect_secret_exposure", secretBase))
	eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
	calls = append(calls, startCall(context.Background(), h.server, "analyze_secret_exposure", secretBase))
	calls = append(calls, startCall(context.Background(), h.server, "detect_secret_exposure", secretBase))
	waitForCallers(t, h, 1, 3)
	h.gate.open()

	for _, c := range calls {
		require.JSONEq(t, want, resultText(t, awaitCall(t, c)))
	}
	require.Equal(t, perCall, h.counter.total(), "the alias must not run the analysis a second time")
}

func TestSecretExposureCoalescing_RequestKeys(t *testing.T) {
	distinct := []map[string]any{
		{"namespace": "other"},
		{"namespace": "prod", "resource_kind": "Deployment"},
		{"namespace": "prod", "resource_kind": "ConfigMap"},
		{"namespace": "prod", "resource_name": "web"},
		{"namespace": "prod", "resource_kind": "Deployment", "resource_name": "web"},
		{"namespace": "prod", "resource_kind": "Pod", "resource_name": "web"},
	}
	// Spelling, case and explicit-empty values that mean the same request.
	equivalent := []map[string]any{
		{"namespace": "prod", "resource_kind": ""},
		{"namespace": "prod", "resource_name": ""},
		{"namespace": "prod", "resource_kind": "", "resource_name": ""},
	}
	t.Run("distinct", func(t *testing.T) {
		requests := append([]map[string]any{secretBase}, distinct...)
		h := newSecretCoalescingHarness(t)
		h.gate.arm()
		var calls []<-chan callOutcome
		for _, args := range requests {
			calls = append(calls, startCall(context.Background(), h.server, secretToolNames[0], args))
		}
		waitForCallers(t, h, len(requests), len(requests))
		eventually(t, "every independent execution to be running", func() bool {
			return h.gate.blocked.Load() == int64(len(requests))
		})
		h.gate.open()
		for _, c := range calls {
			awaitCall(t, c)
		}
	})
	t.Run("equivalent", func(t *testing.T) {
		h := newSecretCoalescingHarness(t)
		h.gate.arm()
		calls := []<-chan callOutcome{startCall(context.Background(), h.server, secretToolNames[0], secretBase)}
		eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
		for _, args := range equivalent {
			calls = append(calls, startCall(context.Background(), h.server, secretToolNames[1], args))
		}
		waitForCallers(t, h, 1, 1+len(equivalent))
		h.gate.open()
		for _, c := range calls {
			awaitCall(t, c)
		}
	})
	t.Run("kind case folds to one key", func(t *testing.T) {
		h := newSecretCoalescingHarness(t)
		h.gate.arm()
		withKind := map[string]any{"namespace": "prod", "resource_kind": "Deployment"}
		calls := []<-chan callOutcome{startCall(context.Background(), h.server, secretToolNames[0], withKind)}
		eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
		calls = append(calls, startCall(context.Background(), h.server, secretToolNames[0],
			map[string]any{"namespace": "prod", "resource_kind": "deployment"}))
		waitForCallers(t, h, 1, 2)
		h.gate.open()
		for _, c := range calls {
			awaitCall(t, c)
		}
	})
}

func TestSecretExposureCoalescing_InvalidRequestsNeverEnterSharedWork(t *testing.T) {
	for _, args := range []map[string]any{
		{},
		{"namespace": "prod", "resource_kind": "Secret"},
		{"namespace": "prod", "resource_name": float64(1)},
	} {
		h := newSecretCoalescingHarness(t)
		h.gate.arm()
		res, err := invokeTool(context.Background(), h.server, secretToolNames[0], args)
		require.NoError(t, err)
		require.True(t, res.IsError)
		require.Empty(t, analysisFlights(h.server))
		require.Zero(t, h.counter.total())
	}
}

func TestSecretExposureCoalescing_CancellationIsPerCaller(t *testing.T) {
	for _, tool := range secretToolNames {
		t.Run(tool, func(t *testing.T) {
			_, want := secretSingleCall(t, tool, secretBase)

			h := newSecretCoalescingHarness(t)
			h.gate.arm()
			cancelCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			leaving := startCall(cancelCtx, h.server, tool, secretBase)
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			staying := startCall(context.Background(), h.server, tool, secretBase)
			waitForCallers(t, h, 1, 2)

			cancel()
			require.True(t, awaitCall(t, leaving).IsError)
			waitForCallers(t, h, 1, 1)
			require.Zero(t, h.gate.cancelled.Load(), "work still needed by another caller must not be cancelled")

			h.gate.open()
			res := awaitCall(t, staying)
			require.False(t, res.IsError)
			require.JSONEq(t, want, resultText(t, res))
		})
	}
}

func TestSecretExposureCoalescing_AllCallersCancelledThenFreshExecution(t *testing.T) {
	perCall, want := secretSingleCall(t, secretToolNames[0], secretBase)

	h := newSecretCoalescingHarness(t)
	h.gate.arm()
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelA()
	defer cancelB()
	a := startCall(ctxA, h.server, secretToolNames[0], secretBase)
	eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
	b := startCall(ctxB, h.server, secretToolNames[1], secretBase)
	waitForCallers(t, h, 1, 2)

	cancelA()
	cancelB()
	require.True(t, awaitCall(t, a).IsError)
	require.True(t, awaitCall(t, b).IsError)
	eventually(t, "parked API request to observe cancellation", func() bool {
		return h.gate.cancelled.Load() >= 1 && h.gate.blocked.Load() == 0
	})
	h.gate.open()
	eventually(t, "abandoned execution to stop", func() bool {
		return h.counter.inFlight.Load() == 0 && len(analysisFlights(h.server)) == 0
	})

	before := h.counter.total()
	res, err := invokeTool(context.Background(), h.server, secretToolNames[0], secretBase)
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(t, res))
	require.JSONEq(t, want, resultText(t, res))
	require.GreaterOrEqual(t, h.counter.total()-before, perCall)
}

func TestSecretExposureCoalescing_ErrorsReachCurrentWaitersAndAreNotRetained(t *testing.T) {
	const callers = 4
	denied := apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "", errors.New("denied"))
	for _, tool := range secretToolNames {
		t.Run(tool, func(t *testing.T) {
			perCall, want := secretSingleCall(t, tool, secretBase)

			h := newSecretCoalescingHarness(t)
			h.gate.arm()
			h.counter.hook = func(ctx context.Context) error {
				if err := h.gate.hook(ctx); err != nil {
					return err
				}
				return denied
			}
			calls := []<-chan callOutcome{startCall(context.Background(), h.server, tool, secretBase)}
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			for i := 1; i < callers; i++ {
				calls = append(calls, startCall(context.Background(), h.server, tool, secretBase))
			}
			waitForCallers(t, h, 1, callers)
			h.gate.open()

			var first string
			for i, c := range calls {
				res := awaitCall(t, c)
				require.True(t, res.IsError, "every waiter must see the failure")
				require.Contains(t, resultText(t, res), string(ErrCodeRBACDenied), "error classification is preserved")
				if i == 0 {
					first = resultText(t, res)
				}
				require.Equal(t, first, resultText(t, res))
			}
			eventually(t, "shared state to be released", func() bool { return len(analysisFlights(h.server)) == 0 })

			h.counter.hook = h.gate.hook
			before := h.counter.total()
			res, err := invokeTool(context.Background(), h.server, tool, secretBase)
			require.NoError(t, err)
			require.False(t, res.IsError, resultText(t, res))
			require.JSONEq(t, want, resultText(t, res))
			require.Equal(t, perCall, h.counter.total()-before)
		})
	}
}

func TestSecretExposureCoalescing_SequentialCallsExecuteAgain(t *testing.T) {
	perCall, want := secretSingleCall(t, secretToolNames[0], secretBase)
	h := newSecretCoalescingHarness(t)
	for i := 1; i <= 3; i++ {
		tool := secretToolNames[i%2]
		res, err := invokeTool(context.Background(), h.server, tool, secretBase)
		require.NoError(t, err)
		require.JSONEq(t, want, resultText(t, res))
		require.Equal(t, int64(i)*perCall, h.counter.total(), "call %d must execute, not reuse a prior result", i)
		require.Empty(t, analysisFlights(h.server))
	}
}

func TestSecretExposureCoalescing_CallersCannotMutateEachOthersResults(t *testing.T) {
	tool := secretToolNames[0]
	_, want := secretSingleCall(t, tool, secretBase)

	h := newSecretCoalescingHarness(t)
	h.gate.arm()
	first := startCall(context.Background(), h.server, tool, secretBase)
	eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
	second := startCall(context.Background(), h.server, tool, secretBase)
	waitForCallers(t, h, 1, 2)
	h.gate.open()

	a, b := awaitCall(t, first), awaitCall(t, second)
	sa, sb := a.StructuredContent.(SecretExposureResult), b.StructuredContent.(SecretExposureResult)
	require.NotEmpty(t, sa.Findings)
	// Mutate every reachable piece of a's result.
	sa.Findings[0].MaskedValue = "tampered"
	sa.Findings = append(sa.Findings, SecretFinding{ResourceName: "extra"})
	sa.Warnings = append(sa.Warnings, "extra")
	a.Content[0] = mcp.TextContent{Type: mcp.ContentTypeText, Text: "tampered"}

	require.JSONEq(t, want, resultText(t, b))
	encoded, err := json.Marshal(sb)
	require.NoError(t, err)
	require.JSONEq(t, want, string(encoded))

	res, err := invokeTool(context.Background(), h.server, tool, secretBase)
	require.NoError(t, err)
	require.JSONEq(t, want, resultText(t, res))
}

func TestSecretExposureCoalescing_NotBehindScanSemaphore(t *testing.T) {
	for _, tool := range secretToolNames {
		t.Run(tool, func(t *testing.T) {
			h := newSecretCoalescingHarness(t)
			require.NoError(t, h.server.getScanSem().Acquire(context.Background(), 2))
			defer h.server.getScanSem().Release(2)

			res := awaitCall(t, startCall(context.Background(), h.server, tool, secretBase))
			require.False(t, res.IsError, resultText(t, res))
		})
	}
}

func TestSecretExposureResult_CloneIsDeep(t *testing.T) {
	orig := SecretExposureResult{
		Namespace: "ns",
		Findings:  []SecretFinding{{ResourceName: "a", MaskedValue: "x"}},
		Warnings:  []string{"w"},
	}
	cp := orig.cloneStructured().(SecretExposureResult)
	cp.Findings[0].MaskedValue = "changed"
	cp.Warnings[0] = "changed"
	require.Equal(t, "x", orig.Findings[0].MaskedValue)
	require.Equal(t, "w", orig.Warnings[0])

	// Nil and empty slices keep their identity: the encoded form depends on it.
	var zero SecretExposureResult
	require.Nil(t, zero.cloneStructured().(SecretExposureResult).Findings)
	empty := SecretExposureResult{Findings: []SecretFinding{}}
	require.NotNil(t, empty.cloneStructured().(SecretExposureResult).Findings)
}
