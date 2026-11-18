package lsp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lsp.dev/protocol"
)

// waitLimit only bounds how long a broken test waits; nothing passes by it.
const waitLimit = 10 * time.Second

// fakeScan stands in for the scanner: each scan is announced on started, waits
// for its gate if the test set one, and returns what answer says for its number.
type fakeScan struct {
	calls   atomic.Int32
	running atomic.Int32
	maxRun  atomic.Int32
	started chan int
	// gate, when set, is called with the scan's number, and the scan waits for the
	// channel it returns.
	gate   func(n int) <-chan struct{}
	answer func(n int, paths []string) (scanFindings, error)
	paths  chan []string
}

func newFakeScan(answer func(n int, paths []string) (scanFindings, error)) *fakeScan {
	return &fakeScan{started: make(chan int, 100), paths: make(chan []string, 100), answer: answer}
}

func (f *fakeScan) scan(ctx context.Context, paths []string) (scanFindings, error) {
	n := int(f.calls.Add(1))
	if r := f.running.Add(1); r > f.maxRun.Load() {
		f.maxRun.Store(r)
	}
	defer f.running.Add(-1)
	f.paths <- paths
	f.started <- n
	if f.gate != nil {
		if g := f.gate(n); g != nil {
			select {
			case <-g:
			case <-ctx.Done():
				return scanFindings{}, ctx.Err()
			}
		}
	}
	return f.answer(n, paths)
}

type harness struct {
	t         *testing.T
	barrierOn atomic.Bool
	marker    string
	dir       string
	docs      *documentStore
	c         *coordinator
	published chan *protocol.PublishDiagnosticsParams
	scan      *fakeScan
	cancel    context.CancelFunc
}

func diag(msg string) protocol.Diagnostic {
	return protocol.Diagnostic{Message: protocol.String(msg), Source: protocol.NewOptional("kubescape")}
}

func findingsFor(complete bool, byFile map[string][]protocol.Diagnostic) scanFindings {
	return scanFindings{byFile: byFile, unreliable: map[string]struct{}{}, complete: complete}
}

func newHarness(t *testing.T, scan *fakeScan, withRoot bool) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, docs: newDocumentStore(), scan: scan, published: make(chan *protocol.PublishDiagnosticsParams, 100)}
	orig := scan.answer
	scan.answer = func(n int, paths []string) (scanFindings, error) {
		if h.barrierOn.Load() {
			// The scan of a barrier says something only of the marker, and leaves
			// every other document as it is.
			f := findingsFor(true, map[string][]protocol.Diagnostic{h.marker: {diag("marker")}})
			for _, d := range h.docs.snapshot() {
				if d.path != h.marker {
					f.unreliable[pathKey(d.path)] = struct{}{}
				}
			}
			return f, nil
		}
		return orig(n, paths)
	}
	var roots []string
	if withRoot {
		roots = []string{dir}
	}
	h.c = newCoordinator(h.docs, roots, scan.scan, func(_ context.Context, p *protocol.PublishDiagnosticsParams) error {
		h.published <- p
		return nil
	})
	h.c.debounce = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.c.start(ctx)
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() { h.c.stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(waitLimit):
			t.Error("the coordinator did not stop after its context ended")
		}
	})
	return h
}

// file makes a manifest in the workspace and opens it at version 1.
func (h *harness) file(name string) string {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	require.NoError(h.t, os.WriteFile(p, []byte("kind: Pod\n"), 0o600))
	h.docs.open(uriFromPath(p), p, 1, false)
	return p
}

// save is what the server does for a save.
func (h *harness) save(path string) {
	h.t.Helper()
	d, ok := h.docs.saved(path)
	require.True(h.t, ok)
	h.c.saved(d)
}

func (h *harness) nextPublish() *protocol.PublishDiagnosticsParams {
	h.t.Helper()
	select {
	case p := <-h.published:
		return p
	case <-time.After(waitLimit):
		h.t.Fatal("no diagnostics were published")
		return nil
	}
}

// barrier waits until the coordinator has dealt with everything signalled before
// it, and returns what it published meanwhile, before the barrier's own
// diagnostics. It saves a marker document, whose scan is the last: the
// coordinator is one goroutine, so whatever it was going to publish for earlier
// saves has been published when the marker's is.
func (h *harness) barrier() []*protocol.PublishDiagnosticsParams {
	h.t.Helper()
	if h.marker == "" {
		h.marker = h.file("zz-marker.yaml")
	}
	h.barrierOn.Store(true)
	defer h.barrierOn.Store(false)
	h.save(h.marker)
	var before []*protocol.PublishDiagnosticsParams
	for {
		p := h.nextPublish()
		if string(p.URI) == uriFromPath(h.marker) {
			return before
		}
		before = append(before, p)
	}
}

func (h *harness) waitScan() int {
	h.t.Helper()
	select {
	case n := <-h.scan.started:
		return n
	case <-time.After(waitLimit):
		h.t.Fatal("no scan started")
		return 0
	}
}

func mustPath(t *testing.T, uri string) string {
	t.Helper()
	p, err := pathFromURI(uri)
	require.NoError(t, err)
	return p
}

func messages(p *protocol.PublishDiagnosticsParams) []string {
	var out []string
	for _, d := range p.Diagnostics {
		out = append(out, messageString(d))
	}
	return out
}

func TestSaveScansAndPublishesToTheOpenDocumentWithItsVersion(t *testing.T) {
	var path string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("one")}}), nil
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")

	h.save(path)
	p := h.nextPublish()

	assert.Equal(t, uriFromPath(path), string(p.URI))
	assert.Equal(t, []string{"one"}, messages(p))
	version, ok := p.Version.Get()
	assert.True(t, ok)
	assert.Equal(t, int32(1), version)
	assert.Equal(t, []string{h.dir}, <-scan.paths, "the workspace is what is scanned, not the saved file")
}

func TestRapidSavesAreOneScan(t *testing.T) {
	var path string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("x")}}), nil
	})
	h := newHarness(t, scan, true)
	h.c.debounce = 300 * time.Millisecond
	path = h.file("pod.yaml")

	for range 20 {
		h.save(path)
	}
	h.nextPublish()
	assert.Equal(t, int32(1), scan.calls.Load(), "twenty saves inside the debounce are one scan")
}

func TestANewerSaveCancelsTheScanInProgressAndOnlyTheNewerIsPublished(t *testing.T) {
	var path string
	hold := make(chan struct{})
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag([]string{"", "old", "new"}[n])}}), nil
	})
	scan.gate = func(n int) <-chan struct{} {
		if n == 1 {
			return hold // ends only when the scan is cancelled
		}
		return nil
	}
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")

	h.save(path)
	assert.Equal(t, 1, h.waitScan())
	h.save(path) // the first scan is obsolete: its context is cancelled

	assert.Equal(t, []string{"new"}, messages(h.nextPublish()))
	assert.Equal(t, int32(1), scan.maxRun.Load(), "scans never overlap")
	assert.Empty(t, h.barrier())
}

// A scan that does not stop when it is cancelled still cannot publish: its
// result is of an older generation.
func TestAnObsoleteScanThatIgnoresCancellationIsNotPublished(t *testing.T) {
	var path string
	release := make(chan struct{})
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		if n == 1 {
			<-release // does not look at its context
		}
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag([]string{"", "old", "new"}[n])}}), nil
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")

	h.save(path)
	assert.Equal(t, 1, h.waitScan())
	h.save(path)
	close(release)

	assert.Equal(t, []string{"new"}, messages(h.nextPublish()))
	assert.Empty(t, h.barrier())
}

// The scan reads the disk. A change made in the editor after the save is not in
// it, and its findings are not for the document as it now is.
func TestAChangeAfterTheSaveSuppressesThatDocumentsResult(t *testing.T) {
	var path, other string
	proceed := make(chan struct{})
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("stale")}, other: {diag("fine")}}), nil
	})
	scan.gate = func(int) <-chan struct{} { return proceed }
	h := newHarness(t, scan, true)
	path, other = h.file("pod.yaml"), h.file("other.yaml")

	h.save(path)
	h.waitScan()
	h.docs.change(path, 2)
	close(proceed)

	p := h.nextPublish()
	assert.Equal(t, uriFromPath(other), string(p.URI), "the document that changed is left alone")
	assert.Empty(t, h.barrier())
}

func TestADocumentWithUnsavedChangesIsLeftAlone(t *testing.T) {
	var dirty, clean string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{dirty: {diag("d")}, clean: {diag("c")}}), nil
	})
	h := newHarness(t, scan, true)
	dirty, clean = h.file("dirty.yaml"), h.file("clean.yaml")
	h.docs.change(dirty, 2) // typed, not saved

	h.save(clean)
	p := h.nextPublish()
	assert.Equal(t, uriFromPath(clean), string(p.URI))
	assert.Empty(t, h.barrier())
}

func TestPendingSaveDoesNotBelongToAReopenedDocument(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		name := "clean"
		if dirty {
			name = "unsaved changes"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pod.yaml")
			docs := newDocumentStore()
			docs.open(uriFromPath(path), path, 1)
			require.True(t, docs.change(path, 2))
			saved, ok := docs.saved(path)
			require.True(t, ok)
			var published []*protocol.PublishDiagnosticsParams
			c := newCoordinator(docs, []string{filepath.Dir(path)}, func(context.Context, []string) (scanFindings, error) {
				return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("disk finding")}}), nil
			}, func(_ context.Context, p *protocol.PublishDiagnosticsParams) error {
				published = append(published, p)
				return nil
			})
			c.saved(saved)
			_, ok = docs.close(path)
			require.True(t, ok)
			docs.open(uriFromPath(path), path, 1)
			if dirty {
				require.True(t, docs.change(path, 2))
			}

			// Run the pending scan only after reopening, as if the close and
			// reopen happened before the save's debounce expired.
			c.scanOnce(context.Background())
			if dirty {
				assert.Empty(t, published, "a previous lifecycle's save cannot authorize disk findings for an unsaved buffer")
				return
			}
			require.Len(t, published, 1, "a clean reopened document still receives disk findings")
			assert.Equal(t, []string{"disk finding"}, messages(published[0]))
			version, ok := published[0].Version.Get()
			require.True(t, ok)
			assert.Equal(t, int32(1), version)
		})
	}
}

func TestClosingADocumentClearsItsDiagnostics(t *testing.T) {
	var path string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("x")}}), nil
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")
	h.save(path)
	h.nextPublish()

	d, ok := h.docs.close(path)
	require.True(t, ok)
	h.c.closed(d)
	p := h.nextPublish()
	assert.Equal(t, uriFromPath(path), string(p.URI))
	assert.NotNil(t, p.Diagnostics)
	assert.Empty(t, p.Diagnostics, "an empty list, which is how a document's diagnostics are cleared")
}

func TestNothingIsPublishedForADocumentClosedDuringAScan(t *testing.T) {
	var closing, staying string
	proceed := make(chan struct{})
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{closing: {diag("late")}, staying: {diag("kept")}}), nil
	})
	scan.gate = func(int) <-chan struct{} { return proceed }
	h := newHarness(t, scan, true)
	closing, staying = h.file("closing.yaml"), h.file("staying.yaml")

	h.save(staying)
	h.waitScan()
	d, _ := h.docs.close(closing)
	h.c.closed(d)
	assert.Equal(t, uriFromPath(closing), string(h.nextPublish().URI), "the close's own empty list")
	close(proceed)

	p := h.nextPublish()
	assert.Equal(t, uriFromPath(staying), string(p.URI), "the scan still serves the documents that are open")
	assert.Equal(t, []string{"kept"}, messages(p))
	assert.Empty(t, h.barrier(), "and publishes nothing for the closed one")
}

func TestNothingIsPublishedForADocumentClosedAndReopenedDuringAScan(t *testing.T) {
	var target, staying string
	proceed := make(chan struct{})
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{target: {diag("stale")}, staying: {diag("kept")}}), nil
	})
	scan.gate = func(int) <-chan struct{} { return proceed }
	h := newHarness(t, scan, true)
	target, staying = h.file("target.yaml"), h.file("staying.yaml")

	h.save(staying)
	h.waitScan()

	// Close target and immediately reopen it with the same version (1).
	d, _ := h.docs.close(target)
	h.c.closed(d)
	assert.Equal(t, uriFromPath(target), string(h.nextPublish().URI), "the close's own empty list")

	h.docs.open(uriFromPath(target), target, 1, false)
	close(proceed)

	p := h.nextPublish()
	assert.Equal(t, uriFromPath(staying), string(p.URI), "the scan serves the staying document")
	assert.Equal(t, []string{"kept"}, messages(p))
	assert.Empty(t, h.barrier(), "and publishes nothing for the reopened document whose scan belongs to a prior lifecycle")
}

func TestSymlinkAndRealFileOpenConcurrentlyTrackVersionsIndependently(t *testing.T) {
	var realFile string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{realFile: {diag("vuln")}}), nil
	})
	h := newHarness(t, scan, true)
	realFile = h.file("real.yaml")
	symFile := filepath.Join(h.dir, "symlink.yaml")
	require.NoError(t, os.Symlink(realFile, symFile))

	// Open both real and symlink documents with different versions.
	h.docs.open(uriFromPath(realFile), realFile, 1, false)
	h.docs.open(uriFromPath(symFile), symFile, 2, false)

	h.save(realFile)

	got := map[string]int32{}
	gotMsgs := map[string][]string{}
	for range 2 {
		p := h.nextPublish()
		name := filepath.Base(mustPath(t, string(p.URI)))
		v, ok := p.Version.Get()
		require.True(t, ok)
		got[name] = v
		gotMsgs[name] = messages(p)
	}
	assert.Equal(t, map[string]int32{"real.yaml": 1, "symlink.yaml": 2}, got)
	assert.Equal(t, map[string][]string{"real.yaml": {"vuln"}, "symlink.yaml": {"vuln"}}, gotMsgs)
}

func TestSeveralDocumentsEachGetTheirOwnDiagnostics(t *testing.T) {
	var a, b string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{a: {diag("a1"), diag("a2")}, b: {diag("b1")}}), nil
	})
	h := newHarness(t, scan, true)
	a, b = h.file("a.yaml"), h.file("b.yaml")
	h.file("clean.yaml")

	h.save(a)
	got := map[string][]string{}
	for range 2 {
		p := h.nextPublish()
		got[filepath.Base(mustPath(t, string(p.URI)))] = messages(p)
	}
	assert.Equal(t, map[string][]string{"a.yaml": {"a1", "a2"}, "b.yaml": {"b1"}}, got)
	assert.Empty(t, h.barrier(), "clean.yaml had nothing and has nothing: nothing to say")
}

func TestAFailedScanLeavesDiagnosticsAsTheyWere(t *testing.T) {
	var path string
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		switch n {
		case 1:
			return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("real")}}), nil
		case 2:
			return scanFindings{}, errors.New("the scan failed")
		default:
			return findingsFor(true, nil), nil
		}
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")

	h.save(path)
	assert.Equal(t, []string{"real"}, messages(h.nextPublish()))

	h.save(path) // fails: nothing is published, so nothing is cleared
	assert.Empty(t, h.barrier())
	assert.GreaterOrEqual(t, scan.calls.Load(), int32(2))
}

func TestACompleteScanWithNoFindingsClearsWhatWasPublished(t *testing.T) {
	var path string
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		if n == 1 {
			return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("real")}}), nil
		}
		return findingsFor(true, nil), nil
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")
	h.save(path)
	h.nextPublish()

	h.save(path)
	p := h.nextPublish()
	assert.Equal(t, uriFromPath(path), string(p.URI))
	assert.NotNil(t, p.Diagnostics)
	assert.Empty(t, p.Diagnostics, "the finding is gone, and a complete scan says so")
	assert.Empty(t, h.barrier(), "and it is said once")
}

func TestAnIncompleteScanChangesNothing(t *testing.T) {
	var path string
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		if n == 1 {
			return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("real")}}), nil
		}
		return findingsFor(false, nil), nil // could not evaluate everything: no finding proves nothing
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")
	h.save(path)
	h.nextPublish()

	h.save(path)
	assert.Empty(t, h.barrier())
}

func TestAnUnreadableManifestKeepsItsPreviousDiagnostics(t *testing.T) {
	var path string
	scan := newFakeScan(func(n int, _ []string) (scanFindings, error) {
		if n == 1 {
			return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("real")}}), nil
		}
		f := findingsFor(true, nil)
		f.unreliable[canonicalKey(path)] = struct{}{} // skipped: the manifest no longer parses
		return f, nil
	})
	h := newHarness(t, scan, true)
	path = h.file("pod.yaml")
	h.save(path)
	h.nextPublish()

	h.save(path)
	assert.Empty(t, h.barrier())
}

func TestADocumentOutsideTheWorkspaceIsNotTouched(t *testing.T) {
	scan := newFakeScan(func(int, []string) (scanFindings, error) { return findingsFor(true, nil), nil })
	h := newHarness(t, scan, true)
	inside := h.file("pod.yaml")
	outside := filepath.Join(t.TempDir(), "elsewhere.yaml")
	require.NoError(t, os.WriteFile(outside, []byte("kind: Pod\n"), 0o600))
	h.docs.open(uriFromPath(outside), outside, 1, false)
	h.c.published[pathKey(outside)] = struct{}{} // it has diagnostics

	h.save(inside)
	assert.Empty(t, h.barrier(), "the scan did not look at it, so it does not say it is clean")
}

func TestWithoutWorkspaceFoldersTheOpenDocumentsAreScanned(t *testing.T) {
	var path string
	scan := newFakeScan(func(int, []string) (scanFindings, error) {
		return findingsFor(true, map[string][]protocol.Diagnostic{path: {diag("x")}}), nil
	})
	h := newHarness(t, scan, false)
	path = h.file("pod.yaml")
	h.save(path)
	h.nextPublish()
	assert.Equal(t, []string{path}, <-scan.paths)
}

func TestStopEndsTheCoordinatorEvenDuringAScan(t *testing.T) {
	scan := newFakeScan(func(int, []string) (scanFindings, error) { return findingsFor(true, nil), nil })
	scan.gate = func(int) <-chan struct{} { return make(chan struct{}) } // ends only if cancelled
	h := newHarness(t, scan, true)
	h.save(h.file("pod.yaml"))
	h.waitScan()
	h.cancel() // the cleanup then waits for stop, bounded
}

func TestDedupeRoots(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "b")
	nested := filepath.Join(a, "deep", "er")
	for _, d := range []string{a, b, nested} {
		require.NoError(t, os.MkdirAll(d, 0o750))
	}
	assert.Equal(t, []string{a, b}, dedupeRoots([]string{a, b}))
	assert.Equal(t, []string{a}, dedupeRoots([]string{a, nested}), "a root inside another is covered by it")
	assert.Equal(t, []string{a}, dedupeRoots([]string{nested, a}))
	assert.Equal(t, []string{a, b}, dedupeRoots([]string{a, b, a}), "a repeat is dropped")
	assert.Equal(t, []string{a}, dedupeRoots([]string{a, filepath.Join(a, "..", "a")}))
	assert.Empty(t, dedupeRoots(nil))
}

func TestWithin(t *testing.T) {
	base := t.TempDir()
	assert.True(t, within(base, base))
	assert.True(t, within(base, filepath.Join(base, "x", "y.yaml")))
	assert.False(t, within(base, base+"-other"), "a sibling that shares a prefix is not inside")
	assert.False(t, within(filepath.Join(base, "x"), base))
}

// A document and a scan may name the same file through different paths.
func TestCanonicalKeyFollowsSymlinks(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	require.NoError(t, os.MkdirAll(target, 0o750))
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks are not available:", err)
	}
	assert.Equal(t, canonicalKey(filepath.Join(target, "p.yaml")), canonicalKey(filepath.Join(link, "p.yaml")))
}
