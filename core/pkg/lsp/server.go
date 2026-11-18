// Package lsp is Kubescape's Language Server Protocol server: it publishes the
// findings of a local scan of Kubernetes manifests as diagnostics.
//
// Version 1 is save-triggered. The server tracks the documents the editor opens,
// and when one is saved it scans the workspace as it is on disk, so what is
// scanned is what was saved: text that has not been saved is not scanned.
package lsp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.lsp.dev/jsonrpc2"
	"go.lsp.dev/protocol"
)

type state int

const (
	stateNew      state = iota // before initialize
	stateStarting              // initialized, before the initialized notification
	stateReady
	stateShutdown // after shutdown, before exit
)

// server implements the protocol methods the server supports. Every other
// method is answered "method not found" by the embedded UnimplementedServer, and
// no capability is advertised for it.
type server struct {
	protocol.UnimplementedServer

	scan     func(ctx context.Context, paths []string) (scanFindings, error)
	debounce time.Duration

	docs *documentStore

	mu    sync.Mutex
	state state
	roots []string
	coord *coordinator
	stop  context.CancelFunc // ends the coordinator

	// life is the context of the session, which carries the client; the
	// coordinator's lifetime is derived from it, not from a request's.
	life context.Context

	exit chan int // receives the exit code once, on exit
}

func newServer(scan func(context.Context, []string) (scanFindings, error), debounce time.Duration) *server {
	return &server{
		scan:     scan,
		debounce: debounce,
		docs:     newDocumentStore(),
		exit:     make(chan int, 1),
	}
}

// supported are the methods the server implements. A request for any other is
// answered "method not found" and a notification of any other is dropped, before
// its parameters are looked at: the server does not pretend to handle a method it
// does not implement.
var supported = map[string]bool{
	protocol.MethodInitialize:            true,
	protocol.MethodInitialized:           true,
	protocol.MethodShutdown:              true,
	protocol.MethodExit:                  true,
	protocol.MethodTextDocumentDidOpen:   true,
	protocol.MethodTextDocumentDidChange: true,
	protocol.MethodTextDocumentDidSave:   true,
	protocol.MethodTextDocumentDidClose:  true,
}

// handler is the handler of the connection: the protocol's dispatch, with the
// session's lifecycle and the error codes the specification asks for.
//
// Messages are handled one at a time, in the order they arrive. A notification
// that opens, changes, saves or closes a document is meaningless if it overtakes
// another, so none is handled concurrently.
func (s *server) handler() jsonrpc2.Handler {
	dispatch := protocol.ServerHandler(s, jsonrpc2.MethodNotFoundHandler)
	return func(ctx context.Context, req *jsonrpc2.Request) (any, error) {
		method := req.Method()
		if !supported[method] {
			return jsonrpc2.MethodNotFoundHandler(ctx, req)
		}
		if req.IsCall() && method != protocol.MethodInitialize {
			s.mu.Lock()
			st := s.state
			s.mu.Unlock()
			switch st {
			case stateNew, stateStarting:
				return nil, notInitialized()
			case stateShutdown:
				return nil, jsonrpc2.NewError(jsonrpc2.InvalidRequest, "the server is shut down: only exit is accepted")
			}
		}
		result, err := dispatch(ctx, req)
		if err != nil && !req.IsCall() {
			// A notification has no response to carry an error, and one returned
			// from its handler would end the connection. It is logged, and the
			// session goes on.
			logger.L().Warning("a notification could not be handled", helpers.String("method", method), helpers.Error(err))
			return nil, nil
		}
		if errors.Is(err, jsonrpc2.ErrParse) {
			// The frame was valid JSON; it is the parameters that could not be read.
			return nil, jsonrpc2.Errorf(jsonrpc2.InvalidParams, "invalid parameters for %s: %v", method, err)
		}
		return result, err
	}
}

func notInitialized() error {
	return jsonrpc2.NewError(jsonrpc2.ServerNotInitialized, "the server is not initialized")
}

func (s *server) Initialize(_ context.Context, params *protocol.InitializeParams) (*protocol.InitializeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateNew {
		return nil, jsonrpc2.NewError(jsonrpc2.InvalidRequest, "the server is already initialized")
	}
	s.roots = workspaceRoots(params)
	s.state = stateStarting

	save := protocol.Boolean(true) // a save is reported, without its text
	full := protocol.TextDocumentSyncKindFull
	open := true
	return &protocol.InitializeResult{
		Capabilities: protocol.ServerCapabilities{
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: &open,
				Change:    &full, // to follow document versions; the text is not used
				Save:      save,
			},
		},
		ServerInfo: protocol.ServerInfo{Name: "kubescape"},
	}, nil
}

// workspaceRoots are the folders the client opened, from workspaceFolders or,
// failing that, rootUri. Only local folders can be scanned.
func workspaceRoots(params *protocol.InitializeParams) []string {
	if params == nil {
		return nil
	}
	var roots []string
	if folders, ok := params.WorkspaceFolders.Get(); ok {
		for _, f := range folders {
			if p, err := pathFromURI(string(f.URI)); err == nil {
				roots = append(roots, p)
			}
		}
	}
	// rootUri is deprecated, and is what clients that predate workspaceFolders
	// send.
	if rootURI := params.RootURI; len(roots) == 0 && rootURI != nil { //nolint:staticcheck // see above
		if p, err := pathFromURI(string(*rootURI)); err == nil {
			roots = append(roots, p)
		}
	}
	return roots
}

func (s *server) Initialized(context.Context, *protocol.InitializedParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateStarting {
		return nil
	}
	// A request's context ends with the request; the coordinator lives as long as
	// the session.
	life, cancel := context.WithCancel(s.life)
	client, ok := protocol.ClientFromContext(life)
	if !ok {
		cancel()
		return errors.New("no client to publish diagnostics to")
	}
	s.coord = newCoordinator(s.docs, s.roots, s.scan, client.PublishDiagnostics)
	if s.debounce > 0 {
		s.coord.debounce = s.debounce
	}
	s.stop = cancel
	s.coord.start(life)
	s.state = stateReady
	return nil
}

// ready returns the coordinator if the server is initialized and not shut down.
func (s *server) ready() *coordinator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateReady {
		return nil
	}
	return s.coord
}

func (s *server) Shutdown(context.Context) error {
	s.mu.Lock()
	switch s.state {
	case stateNew, stateStarting:
		s.mu.Unlock()
		return notInitialized()
	case stateShutdown:
		s.mu.Unlock()
		return jsonrpc2.NewError(jsonrpc2.InvalidRequest, "the server is already shut down")
	}
	s.state = stateShutdown
	stop, coord := s.stop, s.coord
	s.mu.Unlock()

	// Scans in progress are cancelled, and nothing is published after this.
	stop()
	coord.stop()
	return nil
}

// Exit ends the session: with code 0 after a shutdown, 1 without one.
func (s *server) Exit(context.Context) error {
	s.mu.Lock()
	code := 1
	if s.state == stateShutdown {
		code = 0
	}
	s.mu.Unlock()
	select {
	case s.exit <- code:
	default:
	}
	return nil
}

func (s *server) DidOpen(_ context.Context, params *protocol.DidOpenTextDocumentParams) error {
	if s.ready() == nil {
		return nil
	}
	item := params.TextDocument
	path, err := pathFromURI(string(item.URI))
	if err != nil {
		logger.L().Debug("ignoring a document that is not a local file", helpers.String("uri", string(item.URI)), helpers.Error(err))
		return nil
	}
	// A document can open with changes that aren't saved yet, as when an editor
	// restores one after a restart. Its lines aren't the file's, so it is left
	// as it is until it is saved, like a document changed since its last save.
	dirty := !matchesDisk(path, item.Text)
	s.docs.open(string(item.URI), path, item.Version, dirty)
	return nil
}

// matchesDisk reports whether text is what the file at path holds. A byte order
// mark, which editors leave out of the text they send, and Windows line endings
// don't count as differences.
func matchesDisk(path, text string) bool {
	data, err := readBounded(path)
	if err != nil {
		return false
	}
	normalize := func(s string) string {
		return strings.ReplaceAll(strings.TrimPrefix(s, "\ufeff"), "\r\n", "\n")
	}
	return normalize(string(data)) == normalize(text)
}

func (s *server) DidChange(_ context.Context, params *protocol.DidChangeTextDocumentParams) error {
	if s.ready() == nil {
		return nil
	}
	path, err := pathFromURI(string(params.TextDocument.URI))
	if err != nil {
		return nil
	}
	// The text is not kept: what is scanned is what is on disk, once saved.
	s.docs.change(path, params.TextDocument.Version)
	return nil
}

func (s *server) DidSave(_ context.Context, params *protocol.DidSaveTextDocumentParams) error {
	coord := s.ready()
	if coord == nil {
		return nil
	}
	path, err := pathFromURI(string(params.TextDocument.URI))
	if err != nil {
		return nil
	}
	if d, open := s.docs.saved(path); open {
		coord.saved(path, d.version)
	}
	return nil
}

func (s *server) DidClose(_ context.Context, params *protocol.DidCloseTextDocumentParams) error {
	coord := s.ready()
	if coord == nil {
		return nil
	}
	path, err := pathFromURI(string(params.TextDocument.URI))
	if err != nil {
		return nil
	}
	if d, open := s.docs.close(path); open {
		coord.closed(d)
	}
	return nil
}

// close ends the coordinator, if it was started. It is safe to call twice.
func (s *server) close() {
	s.mu.Lock()
	stop, coord := s.stop, s.coord
	s.mu.Unlock()
	if stop != nil {
		stop()
		coord.stop()
	}
}
