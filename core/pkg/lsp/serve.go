package lsp

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kubescape/kubescape/v4/core/core"
	"go.lsp.dev/jsonrpc2"
	"go.lsp.dev/protocol"
)

// Scanner scans local manifests: *core.LocalScanner is one. A scanner may be
// asked for one scan at a time, as the server does, and each scan reads the files
// as they are then.
type Scanner interface {
	Scan(ctx context.Context, in core.LocalInput) (*core.ScanResult, error)
}

// Options configures Serve.
type Options struct {
	// Debounce is how long after the last save a scan starts. Zero or less selects
	// a default.
	Debounce time.Duration
}

// Serve speaks LSP over in and out until the client exits, in closes or ctx
// ends. It returns the process exit code the protocol asks for: 0 if the client
// asked for a shutdown before it exited, 1 otherwise.
//
// out must carry nothing but the protocol; whatever else would be written to the
// process's standard output is the caller's to redirect.
func Serve(ctx context.Context, in io.Reader, out io.Writer, scanner Scanner, opts Options) (int, error) {
	if scanner == nil {
		return 1, fmt.Errorf("no scanner")
	}
	return serve(ctx, in, out, scanWith(scanner), opts.Debounce)
}

// serve is Serve with the scan as a function, for tests.
func serve(ctx context.Context, in io.Reader, out io.Writer, scan func(context.Context, []string) (scanFindings, error), debounce time.Duration) (int, error) {
	srv := newServer(scan, debounce)
	// The coordinator can be blocked writing diagnostics to a client that stopped
	// reading, and nothing interrupts that write: the wait for it is bounded, and
	// made once, so the session still ends.
	closeServer := sync.OnceFunc(func() { closeWithin(closerFunc(srv.close), closeLimit) })
	defer closeServer()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn := jsonrpc2.NewConn(jsonrpc2.NewStream(stdio{in, out}), jsonrpc2.WithCodec(codec{}))
	ctx = protocol.WithClient(ctx, protocol.ClientDispatcher(conn))
	srv.life = ctx
	// Not wrapped in protocol.CancelHandler: the server's requests are all
	// answered at once, so there is nothing to cancel, and it derives a context
	// from the request's that outlives the request.
	conn.Go(ctx, srv.handler())
	defer closeWithin(conn, closeLimit)

	select {
	case code := <-srv.exit:
		return code, nil
	case <-conn.Done():
		// The client went away, or sent what cannot be read, without an exit.
		select {
		case code := <-srv.exit:
			return code, nil
		default:
		}
		closeServer()
		return srv.codeWithoutExit(), conn.Err()
	case <-ctx.Done():
		closeServer()
		return srv.codeWithoutExit(), nil
	}
}

// codeWithoutExit is the code for a session that ended without an exit
// notification: 0 if it had been shut down, 1 if not.
func (s *server) codeWithoutExit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stateShutdown {
		return 0
	}
	return 1
}

// scanWith adapts a scanner to what the coordinator needs.
func scanWith(s Scanner) func(context.Context, []string) (scanFindings, error) {
	return func(ctx context.Context, paths []string) (scanFindings, error) {
		result, err := s.Scan(ctx, core.LocalInput{Paths: paths})
		if err != nil {
			return scanFindings{}, err
		}
		return findingsOf(result.Session, result.Coverage), nil
	}
}

// codec encodes and decodes the protocol's messages: the protocol package's own,
// which knows its union types. (protocol.NewServer installs the same, but also
// dispatches messages concurrently, which the server must not.)
type codec struct{}

func (codec) Marshal(v any) ([]byte, error) {
	switch m := v.(type) {
	case jsonrpc2.RawMessage:
		if m == nil {
			return []byte("null"), nil
		}
		return m, nil
	case *jsonrpc2.RawMessage:
		if m == nil || *m == nil {
			return []byte("null"), nil
		}
		return *m, nil
	}
	return protocol.Marshal(v)
}

func (codec) Unmarshal(data []byte, v any) error {
	if p, ok := v.(*jsonrpc2.RawMessage); ok {
		*p = append(jsonrpc2.RawMessage(nil), data...)
		return nil
	}
	return protocol.Unmarshal(data, v)
}

// stdio joins a reader and a writer into the connection a stream needs. Closing
// it closes the reader, if it can be closed, which ends a read that is waiting
// for the client; the writer is left to its owner.
type stdio struct {
	io.Reader
	io.Writer
}

func (s stdio) Close() error {
	if c, ok := s.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// closeLimit bounds how long the end of a session waits for the connection to
// close: a read of a standard input that cannot be interrupted would hold it.
const closeLimit = 2 * time.Second

func closeWithin(c io.Closer, limit time.Duration) {
	done := make(chan struct{})
	go func() {
		_ = c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
	}
}

// closerFunc makes a function that cannot fail an io.Closer, for closeWithin.
type closerFunc func()

func (f closerFunc) Close() error {
	f()
	return nil
}
