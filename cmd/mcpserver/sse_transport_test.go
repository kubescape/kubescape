package mcpserver

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSSEServer serves an MCP server with a single "ping" tool through the
// production SSE transport, and counts how often the tool runs.
func newTestSSEServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	s := server.NewMCPServer("test", "0.0.1", server.WithToolCapabilities(false))
	s.AddTool(mcp.NewTool("ping"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return mcp.NewToolResultText("pong"), nil
	})
	_, handler := newSSEServer(s, "127.0.0.1:0")
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, &calls
}

// openSSE opens the event stream with the given Origin ("" sends none). For a
// 200 response it returns the message endpoint the server announces; the
// stream stays open until the test ends.
func openSSE(t *testing.T, ts *httptest.Server, origin string) (status int, endpoint string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	require.NoError(t, err)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if data, ok := strings.CutPrefix(scanner.Text(), "data: "); ok {
			return resp.StatusCode, data
		}
	}
	t.Fatalf("event stream closed before announcing an endpoint: %v", scanner.Err())
	return 0, ""
}

func postMessage(t *testing.T, ts *httptest.Server, endpoint, origin, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+endpoint, strings.NewReader(body))
	require.NoError(t, err)
	// text/plain is what a page can send without a CORS preflight.
	req.Header.Set("Content-Type", "text/plain")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestSSETransportOrigins(t *testing.T) {
	tests := []struct {
		origin string
		want   int
	}{
		{origin: "", want: http.StatusOK}, // non-browser MCP clients send no Origin
		{origin: "http://localhost:6274", want: http.StatusOK},
		{origin: "http://127.0.0.1:3000", want: http.StatusOK},
		{origin: "http://[::1]:8080", want: http.StatusOK},
		{origin: "https://localhost", want: http.StatusOK},
		{origin: "https://evil.example", want: http.StatusForbidden},
		{origin: "http://localhost.evil.example", want: http.StatusForbidden},
		{origin: "http://127.0.0.1.evil.example", want: http.StatusForbidden},
		{origin: "null", want: http.StatusForbidden}, // sandboxed frames and file: pages
	}
	ts, _ := newTestSSEServer(t)
	for _, tt := range tests {
		name := tt.origin
		if name == "" {
			name = "no Origin"
		}
		t.Run(name, func(t *testing.T) {
			status, _ := openSSE(t, ts, tt.origin)
			assert.Equal(t, tt.want, status)
		})
	}
}

// TestSSETransportRejectsCrossOriginToolCalls follows a web page's attempt to
// call a tool: whatever session it gets hold of, its messages are refused and
// the tool never runs, while the same messages without a foreign Origin work.
func TestSSETransportRejectsCrossOriginToolCalls(t *testing.T) {
	ts, calls := newTestSSEServer(t)
	status, endpoint := openSSE(t, ts, "")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, endpoint, "sessionId=")

	const (
		evil       = "https://evil.example"
		initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
		callPing   = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}`
	)
	assert.Equal(t, http.StatusForbidden, postMessage(t, ts, endpoint, evil, initialize))
	assert.Equal(t, http.StatusForbidden, postMessage(t, ts, endpoint, evil, callPing))
	assert.Zero(t, calls.Load(), "a cross-origin request ran a tool")

	assert.Equal(t, http.StatusAccepted, postMessage(t, ts, endpoint, "", initialize))
	assert.Equal(t, http.StatusAccepted, postMessage(t, ts, endpoint, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	assert.Equal(t, http.StatusAccepted, postMessage(t, ts, endpoint, "", callPing))
	assert.Eventually(t, func() bool { return calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond,
		"a client that sends no Origin must still be able to call tools")
}
