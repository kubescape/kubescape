package lsp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lsp.dev/protocol"
)

// failureHarness is a coordinator with one open document whose scans return
// results in turn, and which records the messages shown to the user.
type failureHarness struct {
	c       *coordinator
	results []error
	scans   int
	shown   []*protocol.ShowMessageParams
}

func newFailureHarness(t *testing.T, results ...error) *failureHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(path, []byte("kind: Pod\n"), 0o600))
	docs := newDocumentStore()
	docs.open(uriFromPath(path), path, 1, false)
	h := &failureHarness{results: results}
	h.c = newCoordinator(docs, []string{filepath.Dir(path)}, func(context.Context, []string) (scanFindings, error) {
		err := h.results[h.scans]
		h.scans++
		if err != nil {
			return scanFindings{}, err
		}
		return findingsFor(true, nil), nil
	}, func(context.Context, *protocol.PublishDiagnosticsParams) error { return nil })
	h.c.notify = func(_ context.Context, p *protocol.ShowMessageParams) error {
		h.shown = append(h.shown, p)
		return nil
	}
	return h
}

// A scan that fails publishes nothing, so without a message an editor would show
// no findings, as if the workspace were clean. The user is told once per
// failure rather than on every save, and again if it recurs after a success.
func TestAFailedScanIsShownToTheUserOnce(t *testing.T) {
	h := newFailureHarness(t,
		errors.New("rules unavailable"),
		errors.New("rules unavailable"), // the same failure again
		errors.New("network down"),      // a different failure
		nil,                             // a success
		errors.New("network down"),      // the failure recurs after it
	)
	for i, want := range []struct {
		shown   bool
		message string
	}{
		{true, "rules unavailable"},
		{false, ""},
		{true, "network down"},
		{false, ""},
		{true, "network down"},
	} {
		before := len(h.shown)
		h.c.scanOnce(context.Background())
		if !want.shown {
			assert.Len(t, h.shown, before, "scan %d: nothing new is shown", i)
			continue
		}
		require.Len(t, h.shown, before+1, "scan %d: one message is shown", i)
		got := h.shown[before]
		assert.Equal(t, protocol.MessageTypeWarning, got.Type, "scan %d", i)
		assert.Contains(t, got.Message, want.message, "scan %d", i)
	}
}

// A message the client could not be sent is not counted as shown: the next
// failed scan tries again.
func TestAScanFailureThatCouldNotBeShownIsRetried(t *testing.T) {
	h := newFailureHarness(t, errors.New("rules unavailable"), errors.New("rules unavailable"))
	attempts := 0
	h.c.notify = func(context.Context, *protocol.ShowMessageParams) error {
		attempts++
		if attempts == 1 {
			return errors.New("client unavailable")
		}
		return nil
	}
	h.c.scanOnce(context.Background())
	h.c.scanOnce(context.Background())
	assert.Equal(t, 2, attempts)
}

// The server sends the warning to the client as window/showMessage.
func TestAFailedScanReachesTheClientAsShowMessage(t *testing.T) {
	s := startSessionWith(t, func(context.Context, []string) (scanFindings, error) {
		return scanFindings{}, errors.New("rules unavailable")
	}, nil)
	s.start()
	_, uri := s.manifest("pod.yaml")
	s.open(uri, 1)
	s.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})
	for {
		m := s.next()
		if m["method"] != "window/showMessage" {
			continue
		}
		params := m["params"].(map[string]any)
		assert.EqualValues(t, protocol.MessageTypeWarning, params["type"])
		assert.Contains(t, params["message"], "rules unavailable")
		return
	}
}
