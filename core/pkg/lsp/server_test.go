package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"
)

// session is a client talking to a server over pipes, frame by frame.
type session struct {
	t       *testing.T
	toSrv   *io.PipeWriter
	frames  chan json.RawMessage // what the server wrote, one frame each
	ended   chan result          // how Serve ended
	cancel  context.CancelFunc
	nextID  int
	dir     string
	scanned chan []string
}

type result struct {
	code int
	err  error
}

func startSession(t *testing.T, answer func(path string) map[string][]protocol.Diagnostic) *session {
	t.Helper()
	var s *session
	return startSessionWith(t, func(ctx context.Context, paths []string) (scanFindings, error) {
		s.scanned <- paths
		var by map[string][]protocol.Diagnostic
		if answer != nil {
			by = answer(s.dir)
		}
		return findingsFor(true, by), nil
	}, func(made *session) { s = made })
}

// startSessionWith starts a session whose scans are scan. made is given the
// session before anything can be scanned.
func startSessionWith(t *testing.T, scan func(context.Context, []string) (scanFindings, error), made func(*session)) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{t: t, toSrv: inW, frames: make(chan json.RawMessage, 100), ended: make(chan result, 1), cancel: cancel, dir: t.TempDir(), scanned: make(chan []string, 100)}
	if made != nil {
		made(s)
	}
	go func() {
		code, err := serve(ctx, inR, outW, scan, 5*time.Millisecond)
		outW.Close()
		s.ended <- result{code, err}
	}()
	go func() {
		r := bufio.NewReader(outR)
		for {
			frame, err := readFrame(r)
			if err != nil {
				close(s.frames)
				return
			}
			s.frames <- frame
		}
	}()
	t.Cleanup(func() {
		cancel()
		inW.Close()
		select {
		case <-s.ended:
		case <-time.After(waitLimit):
			t.Error("Serve did not end")
		}
	})
	return s
}

// readFrame reads one LSP frame, and fails on anything that is not one: the
// server's output must be nothing but frames.
func readFrame(r *bufio.Reader) (json.RawMessage, error) {
	length := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("not a header: %q", line)
		}
		if strings.EqualFold(name, "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return nil, err
			}
			length = n
		}
	}
	if length < 0 {
		return nil, fmt.Errorf("a frame without Content-Length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("a frame that is not JSON: %q", body)
	}
	return body, nil
}

func (s *session) sendRaw(body string) {
	s.t.Helper()
	_, err := fmt.Fprintf(s.toSrv, "Content-Length: %d\r\n\r\n%s", len(body), body)
	require.NoError(s.t, err)
}

func (s *session) notify(method string, params any) {
	s.t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	require.NoError(s.t, err)
	s.sendRaw(string(b))
}

// call sends a request and returns the response, skipping notifications.
func (s *session) call(method string, params any) map[string]any {
	s.t.Helper()
	s.nextID++
	id := s.nextID
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, err := json.Marshal(req)
	require.NoError(s.t, err)
	s.sendRaw(string(b))
	return s.responseTo(id)
}

func (s *session) responseTo(id any) map[string]any {
	s.t.Helper()
	for {
		m := s.next()
		if m["method"] != nil {
			continue // a notification
		}
		if fmt.Sprint(m["id"]) == fmt.Sprint(id) {
			return m
		}
	}
}

func (s *session) next() map[string]any {
	s.t.Helper()
	select {
	case frame, ok := <-s.frames:
		require.True(s.t, ok, "the server closed its output")
		var m map[string]any
		require.NoError(s.t, json.Unmarshal(frame, &m))
		return m
	case <-time.After(waitLimit):
		s.t.Fatal("nothing from the server")
		return nil
	}
}

// diagnostics waits for the next publishDiagnostics.
func (s *session) diagnostics() map[string]any {
	s.t.Helper()
	for {
		m := s.next()
		if m["method"] == "textDocument/publishDiagnostics" {
			return m["params"].(map[string]any)
		}
	}
}

func (s *session) initialize() map[string]any {
	s.t.Helper()
	return s.call("initialize", map[string]any{
		"processId":    nil,
		"rootUri":      uriFromPath(s.dir),
		"capabilities": map[string]any{},
	})
}

func (s *session) start() {
	s.t.Helper()
	res := s.initialize()
	require.Nil(s.t, res["error"], "%v", res)
	s.notify("initialized", map[string]any{})
}

func (s *session) manifest(name string) (string, string) {
	s.t.Helper()
	p := filepath.Join(s.dir, name)
	require.NoError(s.t, os.WriteFile(p, []byte("kind: Pod\n"), 0o600))
	return p, uriFromPath(p)
}

// open opens uri with the text on disk, as an editor does for a file it has no
// unsaved changes to.
func (s *session) open(uri string, version int) {
	text := "kind: Pod\n" // for a document that isn't a file on disk
	if path, err := pathFromURI(uri); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			text = string(data)
		}
	}
	s.openWith(uri, version, text)
}

func (s *session) openWith(uri string, version int, text string) {
	s.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "yaml", "version": version, "text": text}})
}

func (s *session) result() result {
	s.t.Helper()
	select {
	case r := <-s.ended:
		s.ended <- r // for the cleanup
		return r
	case <-time.After(waitLimit):
		s.t.Fatal("Serve did not end")
		return result{}
	}
}

func errorCode(t *testing.T, m map[string]any) float64 {
	t.Helper()
	e, ok := m["error"].(map[string]any)
	require.True(t, ok, "expected an error, got %v", m)
	return e["code"].(float64)
}

func TestInitializeAdvertisesOnlyWhatIsImplemented(t *testing.T) {
	s := startSession(t, nil)
	res := s.initialize()
	require.Nil(t, res["error"])
	result := res["result"].(map[string]any)

	caps := result["capabilities"].(map[string]any)
	assert.Equal(t, []string{"textDocumentSync"}, keys(caps), "no capability but document synchronization")
	sync := caps["textDocumentSync"].(map[string]any)
	assert.Equal(t, true, sync["openClose"])
	assert.EqualValues(t, 1, sync["change"], "full document synchronization")
	assert.Equal(t, true, sync["save"])
	assert.Equal(t, "kubescape", result["serverInfo"].(map[string]any)["name"])
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestACompleteSession(t *testing.T) {
	var path string
	s := startSession(t, func(string) map[string][]protocol.Diagnostic {
		return map[string][]protocol.Diagnostic{path: {{
			Range:    protocol.Range{Start: protocol.Position{Line: 3, Character: 2}, End: protocol.Position{Line: 3, Character: 2}},
			Severity: protocol.DiagnosticSeverityWarning,
			Code:     protocol.String("C-0017"),
			Source:   protocol.NewOptional("kubescape"),
			Message:  protocol.String("Immutable container filesystem"),
		}}}
	})
	s.start()
	var uri string
	path, uri = s.manifest("pod.yaml")

	s.open(uri, 1)
	s.notify("textDocument/didChange", map[string]any{
		"textDocument":   map[string]any{"uri": uri, "version": 2},
		"contentChanges": []any{map[string]any{"text": "kind: Pod\n# edited\n"}},
	})
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})

	p := s.diagnostics()
	assert.Equal(t, uri, p["uri"])
	assert.EqualValues(t, 2, p["version"], "the version the document had when it was saved")
	ds := p["diagnostics"].([]any)
	require.Len(t, ds, 1)
	d := ds[0].(map[string]any)
	assert.Equal(t, "C-0017", d["code"])
	assert.Equal(t, "kubescape", d["source"])
	assert.EqualValues(t, 2, d["severity"])
	assert.Equal(t, "Immutable container filesystem", d["message"])
	assert.Equal(t, map[string]any{"line": 3.0, "character": 2.0}, d["range"].(map[string]any)["start"])
	assert.Equal(t, []string{s.dir}, <-s.scanned)

	s.notify("textDocument/didClose", map[string]any{"textDocument": map[string]any{"uri": uri}})
	p = s.diagnostics()
	assert.Equal(t, uri, p["uri"])
	assert.Empty(t, p["diagnostics"], "closing clears the document's diagnostics")

	res := s.call("shutdown", nil)
	assert.Nil(t, res["error"])
	assert.Contains(t, res, "result", "a response with a null result")
	assert.Nil(t, res["result"])
	s.notify("exit", nil)
	assert.Equal(t, result{code: 0}, s.result())
}

func TestExitWithoutShutdownIsExitCodeOne(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	s.notify("exit", nil)
	assert.Equal(t, 1, s.result().code)
}

func TestRequestsBeforeInitializeAreRefused(t *testing.T) {
	s := startSession(t, nil)
	assert.EqualValues(t, -32002, errorCode(t, s.call("shutdown", nil)), "ServerNotInitialized")
	// Notifications cannot be answered, and are dropped: nothing breaks.
	s.open("file:///x/pod.yaml", 1)
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": "file:///x/pod.yaml"}})
	res := s.initialize()
	assert.Nil(t, res["error"], "the server is still there, and uninitialized")
}

func TestDuplicateInitializeIsAnInvalidRequest(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	assert.EqualValues(t, -32600, errorCode(t, s.initialize()))
}

func TestUnknownMethodsAreNotFound(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	assert.EqualValues(t, -32601, errorCode(t, s.call("textDocument/hover", map[string]any{
		"textDocument": map[string]any{"uri": "file:///x"}, "position": map[string]any{"line": 0, "character": 0},
	})))
	assert.EqualValues(t, -32601, errorCode(t, s.call("kubescape/unknown", nil)))
	// And an unknown notification is dropped without harm.
	s.notify("kubescape/unknownNotification", nil)
	assert.Nil(t, s.call("shutdown", nil)["error"])
}

func TestInvalidParametersAreRefused(t *testing.T) {
	s := startSession(t, nil)
	assert.EqualValues(t, -32602, errorCode(t, s.call("initialize", "not an object")), "InvalidParams")
	s.start()
	s.notify("textDocument/didOpen", "not an object") // a notification: dropped
	assert.Nil(t, s.call("shutdown", nil)["error"], "the session goes on")
}

func TestShutdownTwiceAndRequestsAfterShutdownAreRefused(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	require.Nil(t, s.call("shutdown", nil)["error"])
	assert.EqualValues(t, -32600, errorCode(t, s.call("shutdown", nil)))
	s.notify("exit", nil)
	assert.Equal(t, 0, s.result().code)
}

// The connection library gives up on a frame that is not JSON, and does not
// answer it: the session ends, with the exit code of a session that did not exit.
func TestInvalidJSONEndsTheSession(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	s.sendRaw(`{"jsonrpc": "2.0", "id": 1, "method": `)
	r := s.result()
	assert.Equal(t, 1, r.code)
	assert.Error(t, r.err)
}

func TestAMalformedHeaderEndsTheSessionWithoutAnExit(t *testing.T) {
	s := startSession(t, nil)
	_, err := io.WriteString(s.toSrv, "Not-A-Header\r\n\r\n{}")
	require.NoError(t, err)
	r := s.result()
	assert.Equal(t, 1, r.code)
	assert.Error(t, r.err)
}

func TestClosedInputEndsTheSession(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	s.toSrv.Close()
	assert.Equal(t, 1, s.result().code, "no exit and no shutdown")
}

func TestShutdownThenClosedInputIsAnOrderlyEnd(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	require.Nil(t, s.call("shutdown", nil)["error"])
	s.toSrv.Close()
	assert.Equal(t, 0, s.result().code)
}

func TestCancellingTheContextEndsTheSession(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	s.cancel()
	assert.Equal(t, 1, s.result().code, "without a shutdown")
}

func TestOnlyFileDocumentsAreTracked(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	s.open("untitled:Untitled-1", 1)
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": "untitled:Untitled-1"}})
	require.Nil(t, s.call("shutdown", nil)["error"])
	select {
	case p := <-s.scanned:
		t.Fatalf("a scan for a document that is not a file: %v", p)
	default:
	}
}

func TestSavingADocumentThatIsNotOpenDoesNotScan(t *testing.T) {
	s := startSession(t, nil)
	s.start()
	_, uri := s.manifest("pod.yaml")
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})
	require.Nil(t, s.call("shutdown", nil)["error"])
	select {
	case p := <-s.scanned:
		t.Fatalf("a scan for a document that is not open: %v", p)
	default:
	}
}

// The whole path, with the real scanner: a manifest that fails a control is
// saved, and the editor is told where, how badly and why. No cluster is
// contacted, though a kubeconfig that would reach one is in the environment.
func TestARealScanIsPublishedAndNoClusterIsContacted(t *testing.T) {
	var apiRequests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequests.Add(1)
		http.Error(w, "no cluster", http.StatusInternalServerError)
	}))
	defer api.Close()
	kubeconfig := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: %q}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: t}}]
`, api.URL)), 0o600))
	t.Setenv("KUBECONFIG", kubeconfig)

	scanner := realScanner(t)
	s := startSessionWith(t, scanWith(scanner), nil)
	s.start()
	path, uri := s.manifest("pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte(podManifest("web", false)), 0o600))
	s.open(uri, 1)
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})

	p := s.diagnostics()
	assert.Equal(t, uri, p["uri"])
	ds := p["diagnostics"].([]any)
	require.Len(t, ds, 1)
	d := ds[0].(map[string]any)
	assert.Equal(t, "C-0017", d["code"])
	assert.Equal(t, "kubescape", d["source"])
	assert.EqualValues(t, 7, d["range"].(map[string]any)["start"].(map[string]any)["line"])

	// Fixed and saved: the finding is gone, and a complete scan says so.
	require.NoError(t, os.WriteFile(path, []byte(podManifest("web", true)), 0o600))
	s.notify("textDocument/didChange", map[string]any{
		"textDocument":   map[string]any{"uri": uri, "version": 2},
		"contentChanges": []any{map[string]any{"text": podManifest("web", true)}},
	})
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})
	p = s.diagnostics()
	assert.Empty(t, p["diagnostics"])
	assert.EqualValues(t, 2, p["version"])

	require.Nil(t, s.call("shutdown", nil)["error"])
	assert.Zero(t, apiRequests.Load(), "the cluster was never asked anything")
}

// A document can open with changes that aren't saved, as when an editor restores
// one after a restart. Its lines aren't the file's, so it is dirty until it is
// saved, and the findings read from the file aren't put on it.
func TestADocumentOpenedWithUnsavedChangesIsDirty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte("\xef\xbb\xbfapiVersion: v1\r\nkind: Pod\r\n"), 0o600))
	srv := newServer(nil, 0)
	srv.state = stateReady
	srv.coord = newCoordinator(srv.docs, nil, nil, nil)
	open := func(text string) document {
		t.Helper()
		item := protocol.TextDocumentItem{URI: uri.URI(uriFromPath(path)), LanguageID: "yaml", Version: 1, Text: text}
		require.NoError(t, srv.DidOpen(context.Background(), &protocol.DidOpenTextDocumentParams{TextDocument: item}))
		d, ok := srv.docs.get(path)
		require.True(t, ok)
		return d
	}

	assert.False(t, open("apiVersion: v1\nkind: Pod\n").dirty, "the text on disk, but for its byte order mark and line endings")
	assert.True(t, open("# restored, not saved\napiVersion: v1\nkind: Pod\n").dirty)
}

func TestDidOpenWithUnsavedChangesIsNeverObservedClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: v1\nkind: Pod\n"), 0o600))
	srv := newServer(nil, 0)
	srv.state = stateReady
	srv.coord = newCoordinator(srv.docs, nil, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var observedClean atomic.Bool
	var wg sync.WaitGroup

	// Reader goroutines continuously inspect the document store.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if d, ok := srv.docs.get(path); ok && !d.dirty {
					observedClean.Store(true)
				}
				for _, d := range srv.docs.snapshot() {
					if d.path == path && !d.dirty {
						observedClean.Store(true)
					}
				}
			}
		}()
	}

	// Writer opens with unsaved text and closes repeatedly.
	for i := 0; i < 50 && ctx.Err() == nil; i++ {
		item := protocol.TextDocumentItem{
			URI:        uri.URI(uriFromPath(path)),
			LanguageID: "yaml",
			Version:    int32(i + 1),
			Text:       "# unsaved edit\napiVersion: v1\nkind: Pod\n",
		}
		require.NoError(t, srv.DidOpen(ctx, &protocol.DidOpenTextDocumentParams{TextDocument: item}))
		srv.docs.close(path)
	}
	cancel()
	wg.Wait()

	assert.False(t, observedClean.Load(), "document with unsaved text should never be visible as clean")
}

// A manifest elsewhere in the workspace that doesn't parse is left as it is; it
// doesn't hold back the diagnostics of the others.
func TestAManifestThatDoesNotParseDoesNotHoldBackTheOthers(t *testing.T) {
	s := startSessionWith(t, scanWith(realScanner(t)), nil)
	s.start()
	broken, _ := s.manifest("broken.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("kind: Pod\n  : : not yaml [\n"), 0o600))
	path, uri := s.manifest("pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte(podManifest("web", false)), 0o600))
	s.open(uri, 1)
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})

	ds := s.diagnostics()["diagnostics"].([]any)
	require.Len(t, ds, 1)
	assert.Equal(t, "C-0017", ds[0].(map[string]any)["code"])
}

func TestWorkspaceRoots_NilParams(t *testing.T) {
	assert.Nil(t, workspaceRoots(nil))
}
