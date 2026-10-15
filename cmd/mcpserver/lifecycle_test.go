package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lifecycleWait = 5 * time.Second

// blockTool is a tool that signals when it starts and then waits to be
// released. When honorCtx is set it also returns as soon as its context ends,
// recording why.
type blockTool struct {
	started  chan struct{}
	release  chan struct{}
	ctxErr   chan error
	honorCtx bool
}

func newBlockTool(honorCtx bool) *blockTool {
	return &blockTool{
		started:  make(chan struct{}, 8),
		release:  make(chan struct{}),
		ctxErr:   make(chan error, 8),
		honorCtx: honorCtx,
	}
}

func (b *blockTool) handler(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	b.started <- struct{}{}
	var done <-chan struct{}
	if b.honorCtx {
		done = ctx.Done()
	}
	select {
	case <-b.release:
		return mcp.NewToolResultText("released"), nil
	case <-done:
		b.ctxErr <- ctx.Err()
		return mcp.NewToolResultText("cancelled"), nil
	}
}

func newLifecycleMCPServer(work *workLifecycle, bt *blockTool) *server.MCPServer {
	opts := append([]server.ServerOption{server.WithToolCapabilities(false)},
		lifecycleServerOptions("sse", func() *workLifecycle { return work })...)
	s := server.NewMCPServer("test", "0.0.1", opts...)
	s.AddTool(mcp.NewTool("block"), bt.handler)
	s.AddTool(mcp.NewTool("ping"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("pong"), nil
	})
	return s
}

type runningSSE struct {
	addr   string
	cancel context.CancelFunc
	done   chan error
	work   *workLifecycle
}

func runSSE(t *testing.T, s *server.MCPServer, work *workLifecycle, drain, timeout time.Duration) *runningSSE {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningSSE{addr: ln.Addr().String(), cancel: cancel, done: make(chan error, 1), work: work}
	transport := newSSETransport(s, r.addr)
	go func() { r.done <- serveSSEUntilShutdown(ctx, transport, ln, work, drain, timeout) }()
	t.Cleanup(cancel)
	return r
}

func (r *runningSSE) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(lifecycleWait):
		t.Fatal("serveSSEUntilShutdown did not return")
		return nil
	}
}

// sseClient is one SSE session: the open event stream plus a client for the
// message endpoint. Stream payloads arrive on data; eof closes when the
// server ends the stream.
type sseClient struct {
	t        *testing.T
	http     *http.Client
	base     string
	endpoint string
	data     chan string
	eof      chan struct{}
}

func openSSEClient(t *testing.T, addr string) *sseClient {
	t.Helper()
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	c := &sseClient{
		t:    t,
		http: &http.Client{Transport: transport},
		base: "http://" + addr,
		data: make(chan string, 64),
		eof:  make(chan struct{}),
	}
	streamTransport := &http.Transport{}
	t.Cleanup(streamTransport.CloseIdleConnections)
	resp, err := (&http.Client{Transport: streamTransport}).Get(c.base + "/sse")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Cleanup(func() { _ = resp.Body.Close() })
	go func() {
		defer close(c.eof)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if payload, ok := strings.CutPrefix(scanner.Text(), "data:"); ok {
				c.data <- strings.TrimSpace(payload)
			}
		}
	}()
	c.endpoint = c.next()
	require.Contains(t, c.endpoint, "sessionId=")
	return c
}

func (c *sseClient) next() string {
	c.t.Helper()
	select {
	case d := <-c.data:
		return d
	case <-time.After(lifecycleWait):
		c.t.Fatal("no event from the SSE stream")
		return ""
	}
}

// reply reads events until the JSON-RPC response with the given id arrives.
func (c *sseClient) reply(id int) string {
	c.t.Helper()
	for {
		payload := c.next()
		var msg struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(payload), &msg) == nil && string(msg.ID) == fmt.Sprint(id) {
			return payload
		}
	}
}

func (c *sseClient) post(body string) {
	c.t.Helper()
	resp, err := c.http.Post(c.base+c.endpoint, "application/json", strings.NewReader(body))
	require.NoError(c.t, err)
	_ = resp.Body.Close()
	require.Equal(c.t, http.StatusAccepted, resp.StatusCode)
}

func (c *sseClient) initialize() {
	c.t.Helper()
	c.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	c.reply(1)
	c.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func (c *sseClient) call(id int, tool string) {
	c.t.Helper()
	c.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, id, tool))
}

func (c *sseClient) waitClosed() {
	c.t.Helper()
	select {
	case <-c.eof:
	case <-time.After(lifecycleWait):
		c.t.Fatal("the SSE stream was not closed")
	}
}

func isDraining(w *workLifecycle) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.draining
}

func TestSSEShutdown_ClosesStreamsAndStopsAccepting(t *testing.T) {
	work := &workLifecycle{}
	r := runSSE(t, newLifecycleMCPServer(work, newBlockTool(true)), work, time.Second, 3*time.Second)
	c := openSSEClient(t, r.addr)

	r.cancel()

	c.waitClosed()
	require.NoError(t, r.result(t), "a requested shutdown is not an error")
	conn, err := net.DialTimeout("tcp", r.addr, time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "the listener must be closed once shutdown returns")
}

// The flush grace is not skipped merely because no tracked work is running when
// shutdown begins: mcp-go queues and writes a response after its handler has
// returned, so an idle lifecycle does not mean the stream is flushed. The
// grace is a lower bound on how long shutdown takes, so this does not depend on
// scheduling.
func TestSSEShutdown_AppliesFlushGraceWhenIdle(t *testing.T) {
	work := &workLifecycle{}
	r := runSSE(t, newLifecycleMCPServer(work, newBlockTool(true)), work, time.Second, 3*time.Second)
	c := openSSEClient(t, r.addr)
	require.False(t, work.running())

	start := time.Now()
	r.cancel()
	c.waitClosed()
	require.NoError(t, r.result(t))
	assert.GreaterOrEqual(t, time.Since(start), sseFlushGrace)
}

func TestSSEShutdown_DrainsInFlightCallAndRefusesNewOnes(t *testing.T) {
	bt := newBlockTool(true)
	work := &workLifecycle{}
	r := runSSE(t, newLifecycleMCPServer(work, bt), work, lifecycleWait, 2*lifecycleWait)
	c := openSSEClient(t, r.addr)
	c.initialize()
	c.call(2, "block")
	<-bt.started

	r.cancel()
	require.Eventually(t, func() bool { return isDraining(work) }, lifecycleWait, 5*time.Millisecond)

	// While draining, the stream stays open and new calls are refused.
	c.call(3, "ping")
	refused := c.reply(3)
	assert.Contains(t, refused, string(ErrCodeShuttingDown))
	select {
	case <-r.done:
		t.Fatal("shutdown finished while a tool call was still running")
	default:
	}

	// The running call finishes undisturbed and its result is delivered
	// before the stream is closed.
	close(bt.release)
	assert.Contains(t, c.reply(2), "released")
	select {
	case err := <-bt.ctxErr:
		t.Fatalf("a call that finished within the drain period was cancelled: %v", err)
	default:
	}
	c.waitClosed()
	require.NoError(t, r.result(t))
}

func TestSSEShutdown_CancelsCallAfterDrainPeriod(t *testing.T) {
	bt := newBlockTool(true)
	work := &workLifecycle{}
	r := runSSE(t, newLifecycleMCPServer(work, bt), work, 50*time.Millisecond, 3*time.Second)
	c := openSSEClient(t, r.addr)
	c.initialize()
	c.call(2, "block")
	<-bt.started

	r.cancel()

	select {
	case err := <-bt.ctxErr:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(lifecycleWait):
		t.Fatal("the in-flight call was never cancelled")
	}
	require.NoError(t, r.result(t), "work that honours cancellation is joined cleanly")
}

func TestSSEShutdown_ReportsWorkThatIgnoresCancellation(t *testing.T) {
	bt := newBlockTool(false)
	work := &workLifecycle{}
	r := runSSE(t, newLifecycleMCPServer(work, bt), work, 10*time.Millisecond, 200*time.Millisecond)
	t.Cleanup(func() {
		select {
		case <-bt.release:
		default:
			close(bt.release)
		}
	})
	c := openSSEClient(t, r.addr)
	c.initialize()
	c.call(2, "block")
	<-bt.started

	r.cancel()

	err := r.result(t)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "mcp work shutdown")
}

type failingListener struct {
	net.Listener
	err error
}

func (l failingListener) Accept() (net.Conn, error) { return nil, l.err }

func TestSSEShutdown_PreservesServeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	want := errors.New("accept failed")
	work := &workLifecycle{}
	s := newLifecycleMCPServer(work, newBlockTool(true))

	err = serveSSEUntilShutdown(context.Background(), newSSETransport(s, "127.0.0.1:0"), failingListener{ln, want}, work, time.Second, time.Second)

	require.ErrorIs(t, err, want, "a serve failure must not be reported as a clean shutdown")
	assert.False(t, work.begin(), "a serve failure must also stop admitting work")
}

func TestWorkLifecycle_RepeatedShutdown(t *testing.T) {
	work := &workLifecycle{}
	require.True(t, work.begin())
	finished := make(chan struct{})
	go func() {
		<-finished
		work.end()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), lifecycleWait)
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- work.shutdown(ctx, time.Second) }()
	require.Eventually(t, func() bool { return isDraining(work) }, lifecycleWait, 5*time.Millisecond)
	second := make(chan error, 1)
	go func() { second <- work.shutdown(ctx, time.Second) }()

	close(finished)
	require.NoError(t, <-first)
	require.NoError(t, <-second)
	require.NoError(t, work.shutdown(ctx, 0), "shutdown after completion is a no-op")
	assert.False(t, work.begin(), "no work is admitted after shutdown")
}

func TestWorkLifecycle_RefusesAfterShutdown(t *testing.T) {
	work := &workLifecycle{}
	require.NoError(t, work.shutdown(context.Background(), 0))

	called := false
	tool := work.toolMiddleware(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return nil, nil
	})
	res, err := tool(context.Background(), mcp.CallToolRequest{})
	require.NoError(t, err)
	require.True(t, res.IsError)
	assert.Contains(t, res.Content[0].(mcp.TextContent).Text, string(ErrCodeShuttingDown))

	resource := work.resourceMiddleware(func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		called = true
		return nil, nil
	})
	_, err = resource(context.Background(), mcp.ReadResourceRequest{})
	require.ErrorIs(t, err, errShuttingDown)
	assert.False(t, called, "refused work must not run")
}

// Shared work is cancelled by shutdown, and not before: one caller leaving
// does not cancel an execution another caller still waits for.
func TestWorkLifecycle_SharedWorkIsCancelledOnlyByShutdown(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	work := &ksServer.work
	started := make(chan struct{})
	scanCtxCh := make(chan context.Context, 1)
	scan := func(ctx context.Context) (interface{}, error) {
		scanCtxCh <- ctx
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	type outcome struct{ err error }
	callerResult := make(chan outcome, 2)
	startCaller := func(parent context.Context) {
		require.True(t, work.begin())
		go func() {
			defer work.end()
			ctx, cancel := work.bind(parent)
			defer cancel()
			_, err := ksServer.doSharedChan(ctx, "shared", false, scan)
			callerResult <- outcome{err}
		}()
	}

	leaver, leave := context.WithCancel(context.Background())
	startCaller(leaver)
	<-started
	scanCtx := <-scanCtxCh
	startCaller(context.Background())
	require.Eventually(t, func() bool {
		ksServer.scanCtxMu.Lock()
		defer ksServer.scanCtxMu.Unlock()
		state := ksServer.scanCtxs["shared"]
		return state != nil && state.count == 2
	}, lifecycleWait, time.Millisecond, "both callers must be waiting on the shared execution")

	leave()
	require.ErrorIs(t, (<-callerResult).err, context.Canceled)
	require.NoError(t, scanCtx.Err(), "a remaining waiter keeps the shared execution alive")

	ctx, cancel := context.WithTimeout(context.Background(), lifecycleWait)
	defer cancel()
	require.NoError(t, work.shutdown(ctx, 10*time.Millisecond))
	require.Error(t, (<-callerResult).err)
	require.ErrorIs(t, scanCtx.Err(), context.Canceled)
}

// An execution that outlives every caller is still part of shutdown: it is
// joined, and shutdown reports it if it does not return.
func TestWorkLifecycle_JoinsSharedWorkAfterCallersLeave(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	work := &ksServer.work
	started := make(chan struct{})
	release := make(chan struct{})
	scan := func(context.Context) (interface{}, error) {
		close(started)
		<-release
		return nil, nil
	}

	require.True(t, work.begin())
	callerCtx, leave := context.WithCancel(context.Background())
	callerDone := make(chan struct{})
	go func() {
		defer close(callerDone)
		defer work.end()
		_, _ = ksServer.doSharedChan(callerCtx, "orphan", false, scan)
	}()
	<-started
	leave()
	<-callerDone

	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, work.shutdown(short, 0), context.DeadlineExceeded,
		"shutdown must not report success while the execution is still running")

	close(release)
	long, cancelLong := context.WithTimeout(context.Background(), lifecycleWait)
	defer cancelLong()
	require.NoError(t, work.shutdown(long, 0))
}

func TestLifecycleServerOptions_OnlyForSSE(t *testing.T) {
	work := &workLifecycle{}
	get := func() *workLifecycle { return work }
	assert.Empty(t, lifecycleServerOptions("stdio", get), "stdio must keep its existing behavior")
	assert.Len(t, lifecycleServerOptions("sse", get), 2)
}

// TestSSEShutdown_Signals runs the SSE shutdown coordinator in a child
// process, wired to signals the way the root command wires them, and checks
// that the first SIGTERM or SIGINT shuts it down and exits cleanly.
func TestSSEShutdown_Signals(t *testing.T) {
	if os.Getenv("KS_MCP_SHUTDOWN_TEST_CHILD") == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		work := &workLifecycle{}
		s := newLifecycleMCPServer(work, newBlockTool(true))
		fmt.Println("ready", ln.Addr())
		if err := serveSSEUntilShutdown(ctx, newSSETransport(s, ln.Addr().String()), ln, work, time.Second, 3*time.Second); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("shutdown complete")
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("delivering SIGTERM/os.Interrupt to a child process is not supported on Windows")
	}
	for _, sig := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			executable, err := os.Executable()
			require.NoError(t, err)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSSEShutdown_Signals$")
			cmd.Env = append(os.Environ(), "KS_MCP_SHUTDOWN_TEST_CHILD=1")
			stdout, err := cmd.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, cmd.Start())
			lines := bufio.NewScanner(stdout)
			require.True(t, lines.Scan())
			require.True(t, strings.HasPrefix(lines.Text(), "ready "), lines.Text())
			require.NoError(t, cmd.Process.Signal(sig))
			require.True(t, lines.Scan())
			require.Equal(t, "shutdown complete", lines.Text())
			for lines.Scan() {
			}
			require.NoError(t, cmd.Wait(), "the first signal must end the process cleanly")
		})
	}
}

// A shared execution is registered with its generation, so shutdown cannot
// observe an idle lifecycle in the window between the last caller leaving and
// the execution's goroutine starting. The caller's context is already
// cancelled, and the execution is held until released, so the only ready case
// in the caller's select is cancellation.
func TestWorkLifecycle_SharedWorkIsTrackedBeforeItStarts(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	work := &ksServer.work
	require.True(t, work.begin())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseExec := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseExec)
	ran := make(chan struct{})
	_, err := ksServer.doSharedChan(ctx, "early", false, func(context.Context) (interface{}, error) {
		close(ran)
		<-release
		return nil, nil
	})
	require.ErrorIs(t, err, context.Canceled)
	work.end()

	assert.Equal(t, 1, work.activeCount(), "the departed caller's execution is still tracked")
	sctx, scancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer scancel()
	require.Error(t, work.shutdown(sctx, 10*time.Millisecond), "shutdown must not succeed while the execution runs")

	receiveWithin(t, ran, "execution to start")
	releaseExec()
	sctx2, scancel2 := context.WithTimeout(context.Background(), lifecycleWait)
	defer scancel2()
	require.NoError(t, work.shutdown(sctx2, time.Second))
	assert.Zero(t, work.activeCount())
}

// Joiners of one generation share a single execution that is counted once,
// however many callers join or leave, and the count never goes negative.
func TestWorkLifecycle_GenerationHasOneTrackedExecution(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	work := &ksServer.work
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var executions atomic.Int32
	run := func(context.Context) (interface{}, error) {
		executions.Add(1)
		started <- struct{}{}
		<-release
		return "result", nil
	}

	type outcome struct {
		val interface{}
		err error
	}
	results := make(chan outcome, 2)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() {
		v, err := ksServer.doSharedChan(ctxA, "gen", false, run)
		results <- outcome{v, err}
	}()
	receiveWithin(t, started, "first execution to start")

	// B joins the running generation; Done is read once B is registered.
	joined := make(chan struct{})
	ctxB := &doneObservedContext{Context: context.Background(), observed: joined}
	go func() {
		v, err := ksServer.doSharedChan(ctxB, "gen", false, run)
		results <- outcome{v, err}
	}()
	receiveWithin(t, joined, "second caller to join the generation")

	// The caller that created the generation leaves; B still needs it.
	cancelA()
	assert.ErrorIs(t, receiveWithin(t, results, "first caller to leave").err, context.Canceled)
	assert.Equal(t, 1, work.activeCount(), "the execution B waits on stays tracked")

	close(release)
	got := receiveWithin(t, results, "second caller's result")
	require.NoError(t, got.err)
	assert.Equal(t, "result", got.val)
	assert.EqualValues(t, 1, executions.Load(), "one generation runs one execution")

	sctx, scancel := context.WithTimeout(context.Background(), lifecycleWait)
	defer scancel()
	require.NoError(t, work.shutdown(sctx, time.Second))
	assert.Zero(t, work.activeCount())
}

// After a generation's execution finishes quickly, a later caller starts a new
// execution for the key. Shutdown must wait for it even after its only caller
// has cancelled, and must not be satisfied by the earlier, finished execution.
func TestWorkLifecycle_ShutdownWaitsForExecutionStartedAfterEarlierOneFinished(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	work := &ksServer.work

	_, err := ksServer.doSharedChan(context.Background(), "k", false, func(context.Context) (interface{}, error) {
		return nil, errors.New("early failure")
	})
	require.Error(t, err)

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseExec := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseExec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ksServer.doSharedChan(ctx, "k", false, func(context.Context) (interface{}, error) {
			close(started)
			<-release
			return nil, nil
		})
		done <- err
	}()
	receiveWithin(t, started, "second execution to start")
	cancel()
	assert.ErrorIs(t, receiveWithin(t, done, "caller to leave"), context.Canceled)
	assert.Equal(t, 1, work.activeCount())

	shutdownDone := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), lifecycleWait)
		defer scancel()
		shutdownDone <- work.shutdown(sctx, time.Second)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned %v while an execution was still running", err)
	case <-time.After(100 * time.Millisecond):
	}
	assert.Equal(t, 1, work.activeCount())

	releaseExec()
	require.NoError(t, receiveWithin(t, shutdownDone, "shutdown to finish"))
	assert.Zero(t, work.activeCount())
}
