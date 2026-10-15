package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// mcpDrainPeriod is how long in-flight tool calls may keep running after
	// shutdown begins, with their SSE streams still open so results reach the
	// client. Once it elapses, outstanding work is cancelled.
	mcpDrainPeriod = 20 * time.Second
	// mcpShutdownTimeout bounds the whole shutdown, drain included. It stays
	// below the usual 30s Kubernetes termination grace period.
	mcpShutdownTimeout = 25 * time.Second
	// sseFlushGrace is how long the streams stay open after the last tool call
	// returns. mcp-go queues and writes a call's response after the handler
	// has returned, and exposes no signal for when that is done, so closing
	// the sessions immediately could drop the final results.
	sseFlushGrace = 200 * time.Millisecond
)

// errShuttingDown is returned to resource reads, and reported to tool calls as
// SERVER_SHUTTING_DOWN, once shutdown has begun.
var errShuttingDown = errors.New("MCP server is shutting down")

// workLifecycle owns the work started on behalf of MCP requests: tool calls,
// resource reads, and the shared executions behind them.
//
// mcp-go runs SSE message handlers on goroutines detached from both the HTTP
// request and the session, so stopping the transport neither waits for nor
// cancels them. This type adds that: it refuses new work once shutdown begins,
// lets running work drain, then cancels what is left and waits for it to
// return.
//
// The zero value is ready to use. An instance is single-use: after shutdown it
// stays closed, so a server that is shut down must not be reused.
type workLifecycle struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	draining bool
	active   int
	waiters  []chan struct{}
}

func (l *workLifecycle) initLocked() {
	if l.ctx == nil {
		l.ctx, l.cancel = context.WithCancel(context.Background())
	}
}

// context returns the context cancelled when shutdown gives up on draining.
func (l *workLifecycle) context() context.Context {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.initLocked()
	return l.ctx
}

// begin registers one unit of work. It reports false once shutdown has begun.
func (l *workLifecycle) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.draining {
		return false
	}
	l.active++
	return true
}

// beginShared registers work spawned by an already registered unit, so it is
// accepted even while draining: refusing it would strand the caller that is
// waiting on it. Because the spawner is still registered, the count cannot
// reach zero between the two. The caller must pair it with end.
func (l *workLifecycle) beginShared() {
	l.mu.Lock()
	l.active++
	l.mu.Unlock()
}

func (l *workLifecycle) end() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.active == 0 {
		for _, w := range l.waiters {
			close(w)
		}
		l.waiters = nil
	}
}

// running reports whether any work is registered.
func (l *workLifecycle) running() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active > 0
}

func (l *workLifecycle) activeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

// idle returns a channel that is closed once no work is registered.
func (l *workLifecycle) idle() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch := make(chan struct{})
	if l.active == 0 {
		close(ch)
		return ch
	}
	l.waiters = append(l.waiters, ch)
	return ch
}

// bind returns a context that ends when either parent does or shutdown stops
// draining, so a detached handler context still observes shutdown.
func (l *workLifecycle) bind(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(l.context(), cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// shutdown stops admitting work, waits up to grace for running work to finish,
// then cancels it and waits until ctx ends. A nil result means all work has
// returned. It is safe to call more than once.
func (l *workLifecycle) shutdown(ctx context.Context, grace time.Duration) error {
	l.mu.Lock()
	l.initLocked()
	l.draining = true
	l.mu.Unlock()

	idle := l.idle()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-idle:
		return nil
	case <-timer.C:
	case <-ctx.Done():
	}

	l.cancel()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		// Prefer an already completed join when completion races the deadline.
		select {
		case <-idle:
			return nil
		default:
			return fmt.Errorf("mcp work shutdown: %w", ctx.Err())
		}
	}
}

func (l *workLifecycle) toolMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !l.begin() {
			return mcpToolError(ErrCodeShuttingDown, errShuttingDown.Error(), nil), nil
		}
		defer l.end()
		ctx, cancel := l.bind(ctx)
		defer cancel()
		return next(ctx, req)
	}
}

func (l *workLifecycle) resourceMiddleware(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
	return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		if !l.begin() {
			return nil, errShuttingDown
		}
		defer l.end()
		ctx, cancel := l.bind(ctx)
		defer cancel()
		return next(ctx, req)
	}
}

// lifecycleServerOptions installs the work lifecycle for transports that need
// it. Only SSE does: stdio is a single client whose handlers stop with the
// process, and mcp-go already owns its signal handling.
func lifecycleServerOptions(transport string, work func() *workLifecycle) []server.ServerOption {
	if transport != "sse" {
		return nil
	}
	return []server.ServerOption{
		server.WithToolHandlerMiddleware(func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
			return work().toolMiddleware(next)
		}),
		server.WithResourceHandlerMiddleware(func(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
			return work().resourceMiddleware(next)
		}),
	}
}

// serveSSEUntilShutdown serves t on ln until ctx is cancelled or serving
// fails, then shuts down in this order:
//
//  1. stop accepting connections, leaving open SSE streams in place;
//  2. refuse new tool calls and let running ones finish for up to drain, so
//     their results can still be delivered;
//  3. cancel whatever is left and wait for it to return;
//  4. after a short flush grace, close the SSE sessions and the HTTP server.
//
// Everything is bounded by timeout. The returned error joins serve, transport
// and work-shutdown failures; a clean, requested shutdown returns nil.
func serveSSEUntilShutdown(ctx context.Context, t *sseTransport, ln net.Listener, work *workLifecycle, drain, timeout time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- t.http.Serve(ln) }()

	var serveErr error
	expectedClose := false
	select {
	case serveErr = <-served:
		// A serve failure still cancels and joins outstanding work, but there
		// is no point waiting for it to drain.
		drain = 0
	case <-ctx.Done():
		expectedClose = true
		logger.L().Info("Shutting down MCP server")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if expectedClose {
		_ = ln.Close()
	}
	hadWork := work.running()
	workErr := work.shutdown(shutdownCtx, drain)
	if hadWork {
		select {
		case <-time.After(sseFlushGrace):
		case <-shutdownCtx.Done():
		}
	}
	httpErr := t.sse.Shutdown(shutdownCtx)
	if expectedClose && errors.Is(httpErr, net.ErrClosed) {
		// Shutdown closes the listeners it tracks, and this one was already
		// closed above to stop accepting while work drained.
		httpErr = nil
	}
	if httpErr != nil {
		httpErr = errors.Join(httpErr, t.http.Close())
	}
	if serveErr == nil {
		serveErr = <-served
	}
	if expectedClose && (errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed)) {
		serveErr = nil
	}
	err := errors.Join(serveErr, httpErr, workErr)
	if err == nil {
		logger.L().Info("MCP server shutdown complete")
	}
	return err
}
