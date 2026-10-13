package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/go-logger/helpers"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordSink collects emitted records safely across goroutines.
type recordSink struct {
	mu      sync.Mutex
	records []toolCallRecord
}

func (s *recordSink) emit(r toolCallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
}

func (s *recordSink) all() []toolCallRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]toolCallRecord(nil), s.records...)
}

// newObservedServer returns an MCP server with recovery and the tool-call
// observer installed the same way mcpServerEntrypoint installs them.
func newObservedServer(t *testing.T, emit func(toolCallRecord)) (*server.MCPServer, *toolCallObserver) {
	t.Helper()
	observer, err := newToolCallObserver("test", emit)
	require.NoError(t, err)
	s := server.NewMCPServer("test", "test",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
		server.WithToolHandlerMiddleware(observer.middleware),
	)
	return s, observer
}

func callObservedTool(t *testing.T, s *server.MCPServer, name string, args map[string]any) mcp.JSONRPCMessage {
	t.Helper()
	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	})
	require.NoError(t, err)
	return s.HandleMessage(context.Background(), message)
}

func observedToolText(t *testing.T, message mcp.JSONRPCMessage) (text string, isError bool) {
	t.Helper()
	response, ok := message.(mcp.JSONRPCResponse)
	require.True(t, ok, "expected a JSON-RPC response, got %#v", message)
	var result *mcp.CallToolResult
	switch r := response.Result.(type) {
	case *mcp.CallToolResult:
		result = r
	case mcp.CallToolResult:
		result = &r
	default:
		require.Failf(t, "unexpected result type", "%T", response.Result)
	}
	require.Len(t, result.Content, 1)
	content, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return content.Text, result.IsError
}

func addTool(s *server.MCPServer, name string, handler server.ToolHandlerFunc) {
	s.AddTool(mcp.NewTool(name, mcp.WithString("namespace")), handler)
}

func TestToolCallObserver_SuccessRecordsMetadataOnly(t *testing.T) {
	sink := &recordSink{}
	s, observer := newObservedServer(t, sink.emit)

	clock := time.Unix(1000, 0)
	var tick int
	observer.now = func() time.Time {
		tick++
		return clock.Add(time.Duration(tick) * 250 * time.Millisecond)
	}

	addTool(s, "demo_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(`{"result":"body-must-not-be-logged"}`), nil
	})

	text, isError := observedToolText(t, callObservedTool(t, s, "demo_tool", map[string]any{"namespace": "payments-prod"}))
	assert.False(t, isError)
	assert.Equal(t, `{"result":"body-must-not-be-logged"}`, text, "the tool result must be returned unchanged")

	records := sink.all()
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, "demo_tool", rec.Tool)
	assert.Equal(t, "test", rec.Transport)
	assert.Equal(t, toolCallOutcomeOK, rec.Outcome)
	assert.Empty(t, rec.ErrorCode)
	assert.Equal(t, 250*time.Millisecond, rec.Duration)
	assert.Equal(t, 0, rec.InFlightIdentical)
	assert.Len(t, rec.Fingerprint, 2*fingerprintBytes)
}

func TestToolCallObserver_RecordNeverContainsArgumentsOrResult(t *testing.T) {
	sink := &recordSink{}
	s, _ := newObservedServer(t, sink.emit)

	addTool(s, "demo_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcpToolError(ErrCodeResourceNotFound, "secret-resource-name not found in secret-namespace",
			map[string]any{"namespace": "secret-namespace", "name": "secret-resource-name"}), nil
	})

	callObservedTool(t, s, "demo_tool", map[string]any{"namespace": "secret-namespace", "name": "secret-resource-name"})

	records := sink.all()
	require.Len(t, records, 1)

	// The record and every field rendered from it must be free of the
	// argument values and of the error text.
	rendered := fmt.Sprintf("%+v", records[0])
	for _, field := range toolCallFields(records[0]) {
		rendered += fmt.Sprintf(" %s=%v", field.Key(), field.Value())
	}
	for _, secret := range []string{"secret-namespace", "secret-resource-name", "not found"} {
		assert.NotContains(t, rendered, secret)
	}
	assert.Equal(t, string(ErrCodeResourceNotFound), records[0].ErrorCode)
}

func TestToolCallObserver_ToolErrorResultIsClassifiedByCode(t *testing.T) {
	sink := &recordSink{}
	s, _ := newObservedServer(t, sink.emit)

	addTool(s, "invalid_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcpToolError(ErrCodeInvalidArgument, "bad input", nil), nil
	})

	_, isError := observedToolText(t, callObservedTool(t, s, "invalid_tool", nil))
	assert.True(t, isError, "an error result must still be an error result")

	records := sink.all()
	require.Len(t, records, 1)
	assert.Equal(t, toolCallOutcomeError, records[0].Outcome)
	assert.Equal(t, string(ErrCodeInvalidArgument), records[0].ErrorCode)
}

func TestToolResultErrorCode_IsBounded(t *testing.T) {
	textResult := func(text string) *mcp.CallToolResult {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{mcp.TextContent{Type: "text", Text: text}}}
	}

	tests := []struct {
		name   string
		result *mcp.CallToolResult
		want   string
	}{
		{"known code", textResult(`{"code":"RBAC_DENIED","message":"x"}`), string(ErrCodeRBACDenied)},
		{"unknown code is not echoed", textResult(`{"code":"leaks-a-namespace-name","message":"x"}`), toolCallErrorUnclassified},
		{"plain text error", textResult("something failed in namespace prod"), toolCallErrorUnclassified},
		{"oversized payload is not parsed", textResult(`{"code":"RBAC_DENIED","message":"` + strings.Repeat("a", maxToolErrorPayloadBytes) + `"}`), toolCallErrorUnclassified},
		{"no content", &mcp.CallToolResult{IsError: true}, toolCallErrorUnclassified},
		{"non-text content", &mcp.CallToolResult{IsError: true, Content: []mcp.Content{mcp.ImageContent{Type: "image"}}}, toolCallErrorUnclassified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toolResultErrorCode(tt.result))
		})
	}
}

func TestToolCallObserver_HandlerErrorIsRecordedAndPropagated(t *testing.T) {
	sink := &recordSink{}
	s, _ := newObservedServer(t, sink.emit)

	addTool(s, "failing_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, errors.New("internal detail with secret-namespace")
	})

	message := callObservedTool(t, s, "failing_tool", nil)
	_, isProtocolError := message.(mcp.JSONRPCError)
	assert.True(t, isProtocolError, "the handler error must still reach the client as a JSON-RPC error")

	records := sink.all()
	require.Len(t, records, 1)
	assert.Equal(t, toolCallOutcomeError, records[0].Outcome)
	assert.Equal(t, toolCallErrorHandler, records[0].ErrorCode)
	assert.NotContains(t, fmt.Sprintf("%+v", records[0]), "secret-namespace")
}

func TestToolCallObserver_PanicIsRecordedAndStillRecovered(t *testing.T) {
	sink := &recordSink{}
	s, observer := newObservedServer(t, sink.emit)

	addTool(s, "panicking_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("boom")
	})

	// WithRecovery turns the panic into a handler error; the observer must
	// neither swallow the panic nor stop it reaching WithRecovery.
	message := callObservedTool(t, s, "panicking_tool", nil)
	_, isProtocolError := message.(mcp.JSONRPCError)
	assert.True(t, isProtocolError)

	records := sink.all()
	require.Len(t, records, 1)
	assert.Equal(t, toolCallOutcomePanic, records[0].Outcome)

	observer.mu.Lock()
	defer observer.mu.Unlock()
	assert.Empty(t, observer.inflight, "a panicking call must not leave an in-flight entry behind")
}

func TestToolCallObserver_OverlappingIdenticalCallsAreCounted(t *testing.T) {
	sink := &recordSink{}
	s, observer := newObservedServer(t, sink.emit)

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	addTool(s, "slow_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entered <- struct{}{}
		<-release
		return mcp.NewToolResultText("ok"), nil
	})

	args := map[string]any{"namespace": "prod"}
	var wg sync.WaitGroup
	call := func() {
		defer wg.Done()
		callObservedTool(t, s, "slow_tool", args)
	}

	wg.Add(1)
	go call()
	<-entered // first call is registered and blocked in the handler

	wg.Add(1)
	go call()
	<-entered // second call has registered while the first is still running

	close(release)
	wg.Wait()

	records := sink.all()
	require.Len(t, records, 2)
	assert.Equal(t, records[0].Fingerprint, records[1].Fingerprint)
	assert.ElementsMatch(t, []int{0, 1}, []int{records[0].InFlightIdentical, records[1].InFlightIdentical})

	observer.mu.Lock()
	defer observer.mu.Unlock()
	assert.Empty(t, observer.inflight)
}

func TestToolCallObserver_SequentialIdenticalCallsDoNotOverlap(t *testing.T) {
	sink := &recordSink{}
	s, _ := newObservedServer(t, sink.emit)
	addTool(s, "demo_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	})

	callObservedTool(t, s, "demo_tool", map[string]any{"namespace": "prod"})
	callObservedTool(t, s, "demo_tool", map[string]any{"namespace": "prod"})

	records := sink.all()
	require.Len(t, records, 2)
	assert.Equal(t, records[0].Fingerprint, records[1].Fingerprint)
	assert.Zero(t, records[0].InFlightIdentical)
	assert.Zero(t, records[1].InFlightIdentical, "a finished call must not count as in flight")
}

func TestToolCallObserver_Fingerprint(t *testing.T) {
	observer, err := newToolCallObserver("test", nil)
	require.NoError(t, err)

	base := observer.fingerprint("tool_a", map[string]any{"namespace": "prod", "min_severity": "High"})
	require.NotEmpty(t, base)

	assert.Equal(t, base, observer.fingerprint("tool_a", map[string]any{"min_severity": "High", "namespace": "prod"}),
		"argument order must not matter")
	assert.NotEqual(t, base, observer.fingerprint("tool_a", map[string]any{"namespace": "dev", "min_severity": "High"}),
		"a different argument value must not share a fingerprint")
	assert.NotEqual(t, base, observer.fingerprint("tool_a", map[string]any{"namespace": "prod"}),
		"a different argument set must not share a fingerprint")
	assert.NotEqual(t, base, observer.fingerprint("tool_b", map[string]any{"namespace": "prod", "min_severity": "High"}),
		"the same arguments on a different tool must not share a fingerprint")

	// Documented limit: defaults are not applied, so an omitted argument and
	// its explicit default are distinct. Equal fingerprints imply equal
	// effective arguments, never the reverse.
	assert.NotEqual(t,
		observer.fingerprint("analyze_vulnerability_exposure", map[string]any{}),
		observer.fingerprint("analyze_vulnerability_exposure", map[string]any{"min_severity": "High"}))

	assert.Equal(t, observer.fingerprint("tool_a", nil), observer.fingerprint("tool_a", map[string]any{}),
		"omitted and empty arguments are the same call")

	other, err := newToolCallObserver("test", nil)
	require.NoError(t, err)
	assert.NotEqual(t, base, other.fingerprint("tool_a", map[string]any{"namespace": "prod", "min_severity": "High"}),
		"fingerprints must be keyed per observer so they cannot be precomputed")

	assert.NotContains(t, base, "prod")
	assert.Empty(t, observer.fingerprint("tool_a", map[string]any{"unencodable": make(chan int)}))
}

func TestToolCallObserver_DifferentArgumentsAreNotCountedAsIdentical(t *testing.T) {
	sink := &recordSink{}
	s, observer := newObservedServer(t, sink.emit)

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	addTool(s, "slow_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entered <- struct{}{}
		<-release
		return mcp.NewToolResultText("ok"), nil
	})

	var wg sync.WaitGroup
	for _, ns := range []string{"prod", "dev"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			callObservedTool(t, s, "slow_tool", map[string]any{"namespace": ns})
		}()
	}
	<-entered
	<-entered
	close(release)
	wg.Wait()

	records := sink.all()
	require.Len(t, records, 2)
	assert.NotEqual(t, records[0].Fingerprint, records[1].Fingerprint)
	assert.Zero(t, records[0].InFlightIdentical)
	assert.Zero(t, records[1].InFlightIdentical)

	observer.mu.Lock()
	defer observer.mu.Unlock()
	assert.Empty(t, observer.inflight)
}

func TestToolCallObserver_ConcurrentCallsAreRaceFree(t *testing.T) {
	sink := &recordSink{}
	s, observer := newObservedServer(t, sink.emit)
	addTool(s, "demo_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	})

	const calls = 64
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			callObservedTool(t, s, "demo_tool", map[string]any{"namespace": fmt.Sprintf("ns-%d", i%4)})
		}()
	}
	wg.Wait()

	assert.Len(t, sink.all(), calls)
	observer.mu.Lock()
	defer observer.mu.Unlock()
	assert.Empty(t, observer.inflight, "every call must be removed from the in-flight set")
}

func TestToolCallObserver_InstrumentationFailureDoesNotChangeResult(t *testing.T) {
	s, observer := newObservedServer(t, func(toolCallRecord) { panic("emit failed") })
	addTool(s, "demo_tool", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("unchanged"), nil
	})

	text, isError := observedToolText(t, callObservedTool(t, s, "demo_tool", map[string]any{"namespace": "prod"}))
	assert.False(t, isError)
	assert.Equal(t, "unchanged", text)

	observer.mu.Lock()
	defer observer.mu.Unlock()
	assert.Empty(t, observer.inflight, "bookkeeping must complete even when emit fails")
}

func TestToolCallObserver_UnencodableArgumentsStillRunTheTool(t *testing.T) {
	sink := &recordSink{}
	observer, err := newToolCallObserver("test", sink.emit)
	require.NoError(t, err)

	handler := observer.middleware(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ran"), nil
	})

	request := mcp.CallToolRequest{}
	request.Params.Name = "demo_tool"
	request.Params.Arguments = map[string]any{"bad": make(chan int)}

	result, err := handler(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, result)

	records := sink.all()
	require.Len(t, records, 1)
	assert.Empty(t, records[0].Fingerprint)
	assert.Equal(t, toolCallOutcomeOK, records[0].Outcome)
}

func TestToolCallObserver_ContextCancellationIsAnError(t *testing.T) {
	sink := &recordSink{}
	observer, err := newToolCallObserver("test", sink.emit)
	require.NoError(t, err)

	handler := observer.middleware(func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := mcp.CallToolRequest{}
	request.Params.Name = "demo_tool"

	_, err = handler(ctx, request)
	assert.ErrorIs(t, err, context.Canceled, "the caller's error must be returned unchanged")

	records := sink.all()
	require.Len(t, records, 1)
	assert.Equal(t, toolCallOutcomeError, records[0].Outcome)
	assert.Equal(t, toolCallErrorHandler, records[0].ErrorCode)
}

// TestToolCallObserver_AnalysisToolResultIsUnchanged installs the observer on
// a real analysis tool and checks the response is byte-for-byte what the tool
// returns without it.
func TestToolCallObserver_AnalysisToolResultIsUnchanged(t *testing.T) {
	args := map[string]any{"namespace": "prod"}
	service := unstructuredServiceWithSelector("prod", "web", "LoadBalancer", map[string]any{"app": "web"})

	plain := newServiceExposureTestServer(t, service)
	plainText, plainIsError := observedToolText(t, dispatchRegisteredTool(t, plain, "analyze_service_exposure", args))

	observed := newServiceExposureTestServer(t, service)
	sink := &recordSink{}
	observer, err := newToolCallObserver("sse", sink.emit)
	require.NoError(t, err)
	observed.s.Use(observer.middleware)
	observedText, observedIsError := observedToolText(t, dispatchRegisteredTool(t, observed, "analyze_service_exposure", args))

	assert.Equal(t, plainIsError, observedIsError)
	assert.Equal(t, plainText, observedText)

	records := sink.all()
	require.Len(t, records, 1)
	assert.Equal(t, "analyze_service_exposure", records[0].Tool)
	assert.Equal(t, "sse", records[0].Transport)
	assert.Equal(t, toolCallOutcomeOK, records[0].Outcome)
}

func TestToolCallFields(t *testing.T) {
	collect := func(rec toolCallRecord) map[string]any {
		out := map[string]any{}
		for _, f := range toolCallFields(rec) {
			out[f.Key()] = f.Value()
		}
		return out
	}

	ok := collect(toolCallRecord{Tool: "t", Transport: "stdio", Outcome: toolCallOutcomeOK, Duration: 1500 * time.Microsecond, Fingerprint: "abcd"})
	assert.Equal(t, "t", ok["tool"])
	assert.Equal(t, "stdio", ok["transport"])
	assert.Equal(t, "ok", ok["outcome"])
	assert.InDelta(t, 1.5, ok["durationMs"], 0.0001)
	assert.Equal(t, 0, ok["inFlightIdentical"])
	assert.Equal(t, "abcd", ok["argsFingerprint"])
	assert.NotContains(t, ok, "errorCode")

	failed := collect(toolCallRecord{Tool: "t", Outcome: toolCallOutcomeError, ErrorCode: "RBAC_DENIED"})
	assert.Equal(t, "RBAC_DENIED", failed["errorCode"])
	assert.NotContains(t, failed, "argsFingerprint")
}

func TestToolCallObserverOptions_OnlyAtDebugLevel(t *testing.T) {
	for _, level := range []string{"", "info", "warning", "error"} {
		assert.Empty(t, toolCallObserverOptions(level, "stdio"), "level %q must not install the recorder", level)
	}
	assert.Len(t, toolCallObserverOptions(helpers.DebugLevel.String(), "stdio"), 1)
}
