package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.lsp.dev/protocol"
)

// A client that stops reading must not keep the session from ending: the
// coordinator is then blocked writing diagnostics, and cancellation cannot
// interrupt that write.
func TestCancellingTheContextEndsTheSessionWhenTheClientStopsReading(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte("kind: Pod\n"), 0o600))
	docURI := uriFromPath(path)

	scanned := make(chan struct{})
	release := make(chan struct{})
	scan := func(context.Context, []string) (scanFindings, error) {
		close(scanned)
		<-release
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("finding")}}), nil
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	go func() {
		_, _ = serve(ctx, inR, outW, scan, 5*time.Millisecond)
		close(ended)
	}()
	t.Cleanup(func() {
		cancel()
		_ = inW.Close()
		_ = outR.Close() // fails the blocked write, so the coordinator ends too
	})

	send := func(msg map[string]any) {
		msg["jsonrpc"] = "2.0"
		body, err := json.Marshal(msg)
		require.NoError(t, err)
		_, err = fmt.Fprintf(inW, "Content-Length: %d\r\n\r\n%s", len(body), body)
		require.NoError(t, err)
	}
	send(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{
		"processId": nil, "rootUri": uriFromPath(dir), "capabilities": map[string]any{},
	}})
	_, err := readFrame(bufio.NewReader(outR))
	require.NoError(t, err)
	send(map[string]any{"method": "initialized", "params": map[string]any{}})
	send(map[string]any{"method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{
		"uri": docURI, "languageId": "yaml", "version": 1, "text": "kind: Pod\n",
	}}})
	send(map[string]any{"method": "textDocument/didSave", "params": map[string]any{"textDocument": map[string]any{"uri": docURI}}})

	// From here on the client reads nothing: publishing the scan's diagnostics
	// blocks.
	select {
	case <-scanned:
	case <-time.After(waitLimit):
		t.Fatal("no scan started")
	}
	close(release)
	time.Sleep(50 * time.Millisecond) // let the coordinator reach the write
	cancel()

	select {
	case <-ended:
	case <-time.After(closeLimit + waitLimit):
		t.Fatal("Serve did not end after its context was cancelled")
	}
}
