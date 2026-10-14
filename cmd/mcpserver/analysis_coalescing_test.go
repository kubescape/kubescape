package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// These tests drive the six analysis tools through the registered MCP handler
// (the real invocation path) against fake clients whose API requests can be
// parked and released explicitly. Synchronization is by barriers and by
// observing the coordination state; no assertion depends on elapsed time.

// apiGate parks every API request issued while it is armed. It lets a test
// hold a shared execution open until all callers have joined it.
type apiGate struct {
	mu        sync.Mutex
	release   chan struct{}
	blocked   atomic.Int64 // requests currently parked
	cancelled atomic.Int64 // requests that left because their context ended
}

func (g *apiGate) hook(ctx context.Context) error {
	g.mu.Lock()
	release := g.release
	g.mu.Unlock()
	if release == nil {
		return nil
	}
	g.blocked.Add(1)
	defer g.blocked.Add(-1)
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		g.cancelled.Add(1)
		return ctx.Err()
	}
}

func (g *apiGate) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.release = make(chan struct{})
}

func (g *apiGate) open() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.release != nil {
		close(g.release)
		g.release = nil
	}
}

type analysisHarness struct {
	server  *KubescapeMcpserver
	counter *apiCounter
	gate    *apiGate
}

func newAnalysisHarness(t *testing.T) *analysisHarness {
	t.Helper()
	h := &analysisHarness{counter: &apiCounter{}, gate: &apiGate{}}
	h.counter.hook = h.gate.hook
	h.server = newProbeServer(t, h.counter)
	t.Cleanup(h.gate.open)
	return h
}

// invokeTool dispatches one tools/call through the registered handler.
func invokeTool(ctx context.Context, ksServer *KubescapeMcpserver, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	msg, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		return nil, err
	}
	resp, ok := ksServer.s.HandleMessage(ctx, msg).(mcp.JSONRPCResponse)
	if !ok {
		return nil, fmt.Errorf("protocol error from %s", tool)
	}
	switch r := resp.Result.(type) {
	case *mcp.CallToolResult:
		return r, nil
	case mcp.CallToolResult:
		return &r, nil
	default:
		return nil, fmt.Errorf("unexpected result type %T", resp.Result)
	}
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return text.Text
}

type callOutcome struct {
	res *mcp.CallToolResult
	err error
}

// startCall runs one invocation on its own goroutine.
func startCall(ctx context.Context, ksServer *KubescapeMcpserver, tool string, args map[string]any) <-chan callOutcome {
	out := make(chan callOutcome, 1)
	go func() {
		res, err := invokeTool(ctx, ksServer, tool, args)
		out <- callOutcome{res, err}
	}()
	return out
}

func awaitCall(t *testing.T, ch <-chan callOutcome) *mcp.CallToolResult {
	t.Helper()
	got := receiveWithin(t, ch, "tool call to return")
	require.NoError(t, got.err)
	return got.res
}

// eventually polls cond, yielding the processor between checks. It has a
// deadline only so a broken implementation fails instead of hanging.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// analysisFlights reports, per coalescing key, how many callers are attached
// to a live shared execution of an analysis tool.
func analysisFlights(ksServer *KubescapeMcpserver) map[string]int {
	ksServer.scanCtxMu.Lock()
	defer ksServer.scanCtxMu.Unlock()
	out := map[string]int{}
	for k, st := range ksServer.scanCtxs {
		if strings.HasPrefix(k, "analysis:") {
			out[k] = st.count
		}
	}
	return out
}

func waitForCallers(t *testing.T, h *analysisHarness, flights, callers int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d callers attached to %d shared executions", callers, flights), func() bool {
		f := analysisFlights(h.server)
		total := 0
		for _, n := range f {
			total += n
		}
		return len(f) == flights && total == callers
	})
}

// analysisToolCases carries, per tool, a representative valid request plus
// the argument sets used for key-isolation checks.
type analysisToolCase struct {
	tool string
	base map[string]any
	// distinct are requests that differ from base (and from each other) in
	// exactly one result-affecting argument; each must run on its own.
	distinct []map[string]any
	// equivalent are requests that must share base's execution because
	// normalization maps them to the same effective request.
	equivalent []map[string]any
}

func with(base map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func without(base map[string]any, keys ...string) map[string]any {
	out := with(base)
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func analysisToolCases() []analysisToolCase {
	rbac := map[string]any{"subject_kind": "ServiceAccount", "namespace": "prod", "name": "app"}
	svc := map[string]any{"namespace": "prod"}
	pss := map[string]any{"namespace": "prod"}
	net := map[string]any{"source_namespace": "prod", "source_pod": "src", "destination_namespace": "prod", "destination_pod": "dst"}
	mut := map[string]any{"namespace": "prod", "name": "web-0", "api_group": "apps", "api_version": "v1", "resource": "deployments"}
	vuln := map[string]any{"namespace": "prod"}
	return []analysisToolCase{
		{
			tool: "analyze_rbac_escalation_paths", base: rbac,
			distinct: []map[string]any{
				with(rbac, "subject_kind", "User"),
				with(rbac, "namespace", "other"),
				with(rbac, "name", "other"),
			},
		},
		{
			tool: "analyze_service_exposure", base: svc,
			distinct: []map[string]any{
				with(svc, "namespace", "other"),
				with(svc, "service_name", "a"),
				with(svc, "service_name", "b"),
			},
			equivalent: []map[string]any{with(svc, "service_name", "")},
		},
		{
			tool: "predict_pss_compliance", base: pss,
			distinct: []map[string]any{
				with(pss, "namespace", "other"),
				with(pss, "level", "Baseline"),
				with(pss, "level", "Privileged"),
				with(pss, "workload_name", "web-0"),
				with(pss, "workload_name", "Deployment/web-0"),
			},
			equivalent: []map[string]any{with(pss, "level", "Restricted")},
		},
		{
			tool: "analyze_network_reachability", base: net,
			distinct: []map[string]any{
				with(net, "source_namespace", "other"),
				with(net, "source_pod", "other"),
				with(net, "destination_namespace", "other"),
				with(net, "destination_pod", "other"),
				with(net, "port", float64(80)),
				with(net, "port", float64(443)),
				with(net, "port", float64(80), "protocol", "UDP"),
			},
			// protocol is ignored without a port, so it must not split the key.
			equivalent: []map[string]any{with(net, "protocol", "UDP")},
		},
		{
			tool: "analyze_mutating_admission_policy_impact", base: mut,
			distinct: []map[string]any{
				with(mut, "namespace", "other"),
				with(mut, "name", "web-1"),
				with(mut, "api_group", ""),
				with(mut, "api_version", "v1beta1"),
				with(mut, "resource", "statefulsets"),
				with(mut, "subresource", "status"),
				with(mut, "operation", "UPDATE"),
				with(mut, "cluster_scoped", true),
			},
			equivalent: []map[string]any{
				with(mut, "operation", "CREATE"),
				with(mut, "operation", "create"),
			},
		},
		{
			tool: "analyze_vulnerability_exposure", base: vuln,
			distinct: []map[string]any{
				with(vuln, "namespace", "other"),
				without(vuln, "namespace"),
				with(vuln, "min_severity", "Low"),
				with(vuln, "min_severity", "Critical"),
			},
			equivalent: []map[string]any{with(vuln, "min_severity", "High")},
		},
	}
}

// singleCallCost measures one invocation's API calls and response on a fresh
// harness, as the baseline the coalesced runs are compared against.
func singleCallCost(t *testing.T, tc analysisToolCase) (calls int64, text string) {
	t.Helper()
	h := newAnalysisHarness(t)
	res, err := invokeTool(context.Background(), h.server, tc.tool, tc.base)
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(t, res))
	return h.counter.total(), resultText(t, res)
}

func TestAnalysisCoalescing_IdenticalRequestsShareOneExecution(t *testing.T) {
	const callers = 16
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			perCall, want := singleCallCost(t, tc)
			require.Positive(t, perCall)

			h := newAnalysisHarness(t)
			h.gate.arm()
			calls := make([]<-chan callOutcome, 0, callers)
			calls = append(calls, startCall(context.Background(), h.server, tc.tool, tc.base))
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			for i := 1; i < callers; i++ {
				calls = append(calls, startCall(context.Background(), h.server, tc.tool, tc.base))
			}
			waitForCallers(t, h, 1, callers)
			require.EqualValues(t, 1, h.gate.blocked.Load(), "joining callers must not issue their own API requests")
			h.gate.open()

			seen := map[*mcp.CallToolResult]struct{}{}
			for _, c := range calls {
				res := awaitCall(t, c)
				require.False(t, res.IsError)
				require.JSONEq(t, want, resultText(t, res))
				seen[res] = struct{}{}
			}
			require.Len(t, seen, callers, "every caller must get its own result object")
			require.Equal(t, perCall, h.counter.total(), "%d callers must cost one execution's API calls", callers)
			eventually(t, "shared state to be released", func() bool { return len(analysisFlights(h.server)) == 0 })
		})
	}
}

func TestAnalysisCoalescing_RequestKeys(t *testing.T) {
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool+"/distinct", func(t *testing.T) {
			// Each variant, alone against the base request, must not join it;
			// together with the base they must all be independent executions
			// that are in flight at the same time.
			requests := append([]map[string]any{tc.base}, tc.distinct...)
			h := newAnalysisHarness(t)
			h.gate.arm()
			var calls []<-chan callOutcome
			for _, args := range requests {
				calls = append(calls, startCall(context.Background(), h.server, tc.tool, args))
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
		if len(tc.equivalent) == 0 {
			continue
		}
		t.Run(tc.tool+"/equivalent", func(t *testing.T) {
			requests := append([]map[string]any{tc.base}, tc.equivalent...)
			h := newAnalysisHarness(t)
			h.gate.arm()
			var calls []<-chan callOutcome
			calls = append(calls, startCall(context.Background(), h.server, tc.tool, requests[0]))
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			for _, args := range requests[1:] {
				calls = append(calls, startCall(context.Background(), h.server, tc.tool, args))
			}
			waitForCallers(t, h, 1, len(requests))
			h.gate.open()
			for _, c := range calls {
				awaitCall(t, c)
			}
		})
	}
}

func TestAnalysisCoalescing_InvalidRequestsNeverEnterSharedWork(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"analyze_rbac_escalation_paths", map[string]any{"subject_kind": "Robot", "name": "x"}},
		{"analyze_service_exposure", map[string]any{}},
		{"predict_pss_compliance", map[string]any{"namespace": "prod", "level": "Bogus"}},
		{"analyze_network_reachability", map[string]any{"source_namespace": "a", "source_pod": "b", "destination_namespace": "c", "destination_pod": "d", "port": float64(0)}},
		{"analyze_mutating_admission_policy_impact", map[string]any{"name": "n", "api_version": "v1", "resource": "pods", "operation": "DELETE", "namespace": "prod"}},
		{"analyze_vulnerability_exposure", map[string]any{"min_severity": "Bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			h := newAnalysisHarness(t)
			h.gate.arm()
			res, err := invokeTool(context.Background(), h.server, tc.tool, tc.args)
			require.NoError(t, err)
			require.True(t, res.IsError)
			require.Empty(t, analysisFlights(h.server))
			require.Zero(t, h.counter.total())
		})
	}
}

func TestAnalysisCoalescing_CancellationIsPerCaller(t *testing.T) {
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			_, want := singleCallCost(t, tc)

			h := newAnalysisHarness(t)
			h.gate.arm()
			cancelCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			leaving := startCall(cancelCtx, h.server, tc.tool, tc.base)
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			staying := startCall(context.Background(), h.server, tc.tool, tc.base)
			waitForCallers(t, h, 1, 2)

			cancel()
			res := awaitCall(t, leaving)
			require.True(t, res.IsError, "the cancelled caller must see an error")
			waitForCallers(t, h, 1, 1)
			require.Zero(t, h.gate.cancelled.Load(), "work still needed by another caller must not be cancelled")

			h.gate.open()
			res = awaitCall(t, staying)
			require.False(t, res.IsError)
			require.JSONEq(t, want, resultText(t, res))
		})
	}
}

func TestAnalysisCoalescing_AllCallersCancelledEndsWorkAndNextCallStartsFresh(t *testing.T) {
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			perCall, want := singleCallCost(t, tc)

			h := newAnalysisHarness(t)
			h.gate.arm()
			ctxA, cancelA := context.WithCancel(context.Background())
			ctxB, cancelB := context.WithCancel(context.Background())
			defer cancelA()
			defer cancelB()
			a := startCall(ctxA, h.server, tc.tool, tc.base)
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			b := startCall(ctxB, h.server, tc.tool, tc.base)
			waitForCallers(t, h, 1, 2)

			cancelA()
			cancelB()
			require.True(t, awaitCall(t, a).IsError)
			require.True(t, awaitCall(t, b).IsError)

			// The abandoned execution observes its context ending. The shared
			// state is released as soon as the last caller leaves, while the
			// execution itself may still be unwinding, so completion is
			// checked through the API requests it was parked on. Discovery
			// requests take no context in client-go, so the mutating tool's
			// parked request is released instead and the next context-aware
			// step stops the run.
			if tc.tool == "analyze_mutating_admission_policy_impact" {
				h.gate.open()
			} else {
				eventually(t, "parked API request to observe cancellation", func() bool {
					return h.gate.cancelled.Load() >= 1 && h.gate.blocked.Load() == 0
				})
				h.gate.open()
			}
			eventually(t, "abandoned execution to stop issuing requests", func() bool {
				return h.gate.blocked.Load() == 0 && h.counter.inFlight.Load() == 0 && len(analysisFlights(h.server)) == 0
			})

			// A later call starts a fresh generation: it does not inherit the
			// cancelled execution's context, and it completes with the right
			// answer at the cost of a full execution.
			before := h.counter.total()
			res, err := invokeTool(context.Background(), h.server, tc.tool, tc.base)
			require.NoError(t, err)
			require.False(t, res.IsError, resultText(t, res))
			require.JSONEq(t, want, resultText(t, res))
			require.GreaterOrEqual(t, h.counter.total()-before, perCall)
		})
	}
}

func TestAnalysisCoalescing_ErrorsReachCurrentWaitersAndAreNotRetained(t *testing.T) {
	const callers = 4
	boom := apierrors.NewForbidden(schema.GroupResource{Resource: "things"}, "x", errors.New("denied"))
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			perCall, want := singleCallCost(t, tc)

			h := newAnalysisHarness(t)
			// Park the failing execution until every caller has joined it, then
			// let it hit the injected error.
			h.gate.arm()
			h.counter.hook = func(ctx context.Context) error {
				if err := h.gate.hook(ctx); err != nil {
					return err
				}
				return boom
			}
			var calls []<-chan callOutcome
			calls = append(calls, startCall(context.Background(), h.server, tc.tool, tc.base))
			eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
			for i := 1; i < callers; i++ {
				calls = append(calls, startCall(context.Background(), h.server, tc.tool, tc.base))
			}
			waitForCallers(t, h, 1, callers)
			h.gate.open()

			var first string
			for i, c := range calls {
				res := awaitCall(t, c)
				require.True(t, res.IsError, "every waiter must see the failure, not a success")
				if i == 0 {
					first = resultText(t, res)
				}
				require.Equal(t, first, resultText(t, res))
			}
			eventually(t, "shared state to be released", func() bool { return len(analysisFlights(h.server)) == 0 })

			// The failure is not remembered: once the cause is gone, the next
			// call executes again and succeeds.
			h.counter.hook = h.gate.hook
			before := h.counter.total()
			res, err := invokeTool(context.Background(), h.server, tc.tool, tc.base)
			require.NoError(t, err)
			require.False(t, res.IsError, resultText(t, res))
			require.JSONEq(t, want, resultText(t, res))
			require.Equal(t, perCall, h.counter.total()-before)
		})
	}
}

func TestAnalysisCoalescing_SequentialCallsExecuteAgain(t *testing.T) {
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			perCall, want := singleCallCost(t, tc)
			h := newAnalysisHarness(t)
			for i := 1; i <= 3; i++ {
				res, err := invokeTool(context.Background(), h.server, tc.tool, tc.base)
				require.NoError(t, err)
				require.JSONEq(t, want, resultText(t, res))
				require.Equal(t, int64(i)*perCall, h.counter.total(), "call %d must execute, not reuse a prior result", i)
				require.Empty(t, analysisFlights(h.server))
			}
		})
	}
}

func TestAnalysisCoalescing_CallersCannotMutateEachOthersResults(t *testing.T) {
	tc := analysisToolCases()[0]
	_, want := singleCallCost(t, tc)

	h := newAnalysisHarness(t)
	h.gate.arm()
	first := startCall(context.Background(), h.server, tc.tool, tc.base)
	eventually(t, "the shared execution to reach the API", func() bool { return h.gate.blocked.Load() == 1 })
	second := startCall(context.Background(), h.server, tc.tool, tc.base)
	waitForCallers(t, h, 1, 2)
	h.gate.open()

	a, b := awaitCall(t, first), awaitCall(t, second)
	require.NotSame(t, a, b)
	a.IsError = true
	a.Content[0] = mcp.TextContent{Type: mcp.ContentTypeText, Text: "tampered"}
	a.Content = append(a.Content, mcp.TextContent{Type: mcp.ContentTypeText, Text: "extra"})

	require.False(t, b.IsError)
	require.JSONEq(t, want, resultText(t, b))

	res, err := invokeTool(context.Background(), h.server, tc.tool, tc.base)
	require.NoError(t, err)
	require.JSONEq(t, want, resultText(t, res))
}

func TestAnalysisCoalescing_NotBehindScanSemaphore(t *testing.T) {
	for _, tc := range analysisToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			h := newAnalysisHarness(t)
			// Occupy every scan slot, as two long framework scans would.
			require.NoError(t, h.server.getScanSem().Acquire(context.Background(), 2))
			defer h.server.getScanSem().Release(2)

			done := startCall(context.Background(), h.server, tc.tool, tc.base)
			res := awaitCall(t, done)
			require.False(t, res.IsError, resultText(t, res))
		})
	}
}

func TestDoAnalysis_PanicBecomesErrorForAllWaitersAndServerSurvives(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	params := url.Values{"x": {"1"}}

	entered := make(chan struct{})
	release := make(chan struct{})
	run := func(context.Context) *mcp.CallToolResult {
		close(entered)
		<-release
		panic("defect in analysis")
	}

	results := make(chan *mcp.CallToolResult, 2)
	go func() { results <- ksServer.doAnalysis(context.Background(), "t", params, run) }()
	receiveWithin(t, entered, "shared execution to start")
	go func() {
		results <- ksServer.doAnalysis(context.Background(), "t", params, func(context.Context) *mcp.CallToolResult {
			t.Error("a joining caller must not run its own execution")
			return nil
		})
	}()
	eventually(t, "second caller to join", func() bool { return analysisFlights(ksServer)[analysisKey("t", params)] == 2 })
	close(release)

	for i := 0; i < 2; i++ {
		res := receiveWithin(t, results, "caller to receive the panic as an error")
		require.True(t, res.IsError)
		require.Contains(t, resultText(t, res), string(ErrCodeScanFailed))
	}
	eventually(t, "shared state to be released", func() bool { return len(analysisFlights(ksServer)) == 0 })

	// The server is intact: the next call executes normally.
	res := ksServer.doAnalysis(context.Background(), "t", params, func(context.Context) *mcp.CallToolResult {
		return mcp.NewToolResultText("ok")
	})
	require.False(t, res.IsError)
	require.Equal(t, "ok", resultText(t, res))
}

func TestDoAnalysis_RejectsResultsItCannotShareSafely(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	cases := map[string]*mcp.CallToolResult{
		"nil":        nil,
		"two items":  {Content: []mcp.Content{mcp.TextContent{Type: mcp.ContentTypeText, Text: "a"}, mcp.TextContent{Type: mcp.ContentTypeText, Text: "b"}}},
		"structured": {Content: []mcp.Content{mcp.TextContent{Type: mcp.ContentTypeText, Text: "a"}}, StructuredContent: map[string]any{"k": "v"}},
		"non-text":   {Content: []mcp.Content{mcp.ImageContent{Type: mcp.ContentTypeImage}}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			res := ksServer.doAnalysis(context.Background(), "t", url.Values{"case": {name}}, func(context.Context) *mcp.CallToolResult { return in })
			require.True(t, res.IsError)
		})
	}
}

func TestAnalysisKey_IsUnambiguous(t *testing.T) {
	a := analysisKey("tool", url.Values{"a": {"x&b=y"}})
	b := analysisKey("tool", url.Values{"a": {"x"}, "b": {"y"}})
	require.NotEqual(t, a, b)
	require.NotEqual(t,
		analysisKey("tool", url.Values{"a": {""}}),
		analysisKey("tool", url.Values{}),
		"an argument supplied as empty must differ from one that is absent")
	require.NotEqual(t, analysisKey("one", url.Values{"a": {"1"}}), analysisKey("two", url.Values{"a": {"1"}}))
}
