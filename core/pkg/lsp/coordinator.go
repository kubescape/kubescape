package lsp

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"
)

// defaultDebounce is how long after the last save a scan starts.
const defaultDebounce = 500 * time.Millisecond

// docTarget tracks the version and open lifecycle generation of a document at the
// time a scan is scheduled.
type docTarget struct {
	version int32
	openID  uint64
}

// coordinator turns saves into scans, and scans into published diagnostics.
//
// One goroutine owns all of it: it waits for a save, waits for the saves to stop
// (the debounce), scans, and publishes. So scans never overlap, results are never
// published out of order, and the only goroutine this starts ends with stop.
//
// A save makes the scan in progress, if any, obsolete: it is cancelled, and a
// result is published only if no save has been made since the scan started (its
// generation is still current), the scan completed, and, for each document, the
// document is still open at the version it had when the scan was scheduled. A
// scan that was cancelled, failed or could not evaluate everything publishes
// nothing, and so clears nothing: an absent finding proves nothing then.
type coordinator struct {
	debounce time.Duration
	scan     func(ctx context.Context, paths []string) (scanFindings, error)
	docs     *documentStore
	publish  func(ctx context.Context, params *protocol.PublishDiagnosticsParams) error
	// roots are the workspace folders, with none contained in another. With none
	// at all, the open documents are what is scanned.
	roots []string

	mu         sync.Mutex
	generation uint64
	cancelScan context.CancelFunc   // of the scan in progress, if any
	saves      map[string]docTarget // target of each document at its latest save, by pathKey
	wake       chan struct{}        // capacity one: a save signals without blocking

	// pubMu orders publishing with a document's close: nothing is published for a
	// document after the empty list that closed it.
	pubMu     sync.Mutex
	published map[string]struct{} // documents that have a non-empty list published

	wg sync.WaitGroup
}

func newCoordinator(docs *documentStore, roots []string, scan func(context.Context, []string) (scanFindings, error), publish func(context.Context, *protocol.PublishDiagnosticsParams) error) *coordinator {
	return &coordinator{
		debounce:  defaultDebounce,
		scan:      scan,
		docs:      docs,
		publish:   publish,
		roots:     dedupeRoots(roots),
		saves:     make(map[string]docTarget),
		wake:      make(chan struct{}, 1),
		published: make(map[string]struct{}),
	}
}

// start runs the coordinator until ctx ends.
func (c *coordinator) start(ctx context.Context) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(ctx)
	}()
}

// stop waits for the coordinator to end, after the context given to start has.
func (c *coordinator) stop() { c.wg.Wait() }

// saved records the document as it was at save time and schedules a scan.
func (c *coordinator) saved(d document) {
	c.mu.Lock()
	c.generation++
	c.saves[pathKey(d.path)] = docTarget{version: d.version, openID: d.openID}
	if c.cancelScan != nil {
		c.cancelScan() // obsolete: its result will not be published
	}
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default: // a scan is already due
	}
}

// closed clears the diagnostics of a document that was closed. It does not
// touch scans in progress: the other documents' results are still wanted, and
// the closed document is no longer published to.
func (c *coordinator) closed(d document) {
	c.mu.Lock()
	delete(c.saves, pathKey(d.path))
	c.mu.Unlock()

	c.pubMu.Lock()
	defer c.pubMu.Unlock()
	delete(c.published, pathKey(d.path))
	c.send(context.Background(), &protocol.PublishDiagnosticsParams{URI: uri.URI(d.uri), Diagnostics: []protocol.Diagnostic{}})
}

func (c *coordinator) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		}
		if !c.settle(ctx) {
			return
		}
		c.scanOnce(ctx)
	}
}

// settle waits until no save has been made for the debounce period. It reports
// false if ctx ended first.
func (c *coordinator) settle(ctx context.Context) bool {
	timer := time.NewTimer(c.debounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-c.wake:
			timer.Reset(c.debounce)
		case <-timer.C:
			return true
		}
	}
}

// scanOnce scans for the saves made so far, and publishes the result if it is
// still wanted.
func (c *coordinator) scanOnce(ctx context.Context) {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c.mu.Lock()
	generation := c.generation
	c.cancelScan = cancel
	saves := c.saves
	c.saves = make(map[string]docTarget)
	c.mu.Unlock()

	// The versions the result will be for: a clean document's, as of the scan's
	// scheduling. A document with unsaved changes is not what is on disk, so it
	// is left as it is. Keyed by pathKey so multiple open documents pointing to
	// the same file (such as symlinks) do not collide.
	expected := make(map[string]docTarget)
	var paths []string
	for _, d := range c.docs.snapshot() {
		if saveTarget, ok := saves[pathKey(d.path)]; ok && saveTarget.openID == d.openID {
			expected[pathKey(d.path)] = saveTarget
		} else if !d.dirty {
			expected[pathKey(d.path)] = docTarget{version: d.version, openID: d.openID}
		}
		paths = append(paths, d.path)
	}
	scanPaths := c.roots
	if len(scanPaths) == 0 {
		scanPaths = existing(paths)
	}
	if len(scanPaths) == 0 {
		return
	}

	findings, err := c.scan(scanCtx, scanPaths)

	c.mu.Lock()
	c.cancelScan = nil
	current := c.generation == generation && scanCtx.Err() == nil
	c.mu.Unlock()
	if err != nil {
		if scanCtx.Err() == nil { // not a cancellation, which is routine
			logger.L().Ctx(ctx).Warning("the scan failed; the diagnostics are left as they were", helpers.Error(err))
		}
		return
	}
	if !current || !findings.complete {
		return
	}
	c.apply(ctx, generation, findings, expected)
}

// apply publishes the findings for the open documents in scope.
func (c *coordinator) apply(ctx context.Context, generation uint64, findings scanFindings, expected map[string]docTarget) {
	byFile := make(map[string][]protocol.Diagnostic, len(findings.byFile))
	for path, ds := range findings.byFile {
		byFile[canonicalKey(path)] = ds
	}
	unreliable := make(map[string]struct{}, len(findings.unreliable))
	for path := range findings.unreliable {
		unreliable[canonicalKey(path)] = struct{}{}
	}

	c.pubMu.Lock()
	defer c.pubMu.Unlock()
	for _, d := range c.docs.snapshot() {
		exp, scanned := expected[pathKey(d.path)]
		if !scanned || !c.inScope(d.path) {
			continue
		}
		canonical := canonicalKey(d.path)
		if _, skip := unreliable[canonical]; skip {
			continue
		}
		// Re-checked for each document, under the publishing lock: a save, or the
		// document's change or close, since the scan was scheduled ends it.
		c.mu.Lock()
		current := c.generation == generation
		c.mu.Unlock()
		if !current {
			return
		}
		if now, open := c.docs.get(d.path); !open || now.openID != exp.openID || now.version != exp.version {
			continue
		}
		diagnostics := byFile[canonical]
		_, had := c.published[pathKey(d.path)]
		if len(diagnostics) == 0 && !had {
			continue
		}
		if diagnostics == nil {
			diagnostics = []protocol.Diagnostic{}
		}
		if len(diagnostics) == 0 {
			delete(c.published, pathKey(d.path))
		} else {
			c.published[pathKey(d.path)] = struct{}{}
		}
		c.send(ctx, &protocol.PublishDiagnosticsParams{
			URI:         uri.URI(d.uri),
			Version:     protocol.NewOptional(exp.version),
			Diagnostics: diagnostics,
		})
	}
}

func (c *coordinator) send(ctx context.Context, params *protocol.PublishDiagnosticsParams) {
	if err := c.publish(ctx, params); err != nil && ctx.Err() == nil {
		logger.L().Ctx(ctx).Warning("could not publish diagnostics", helpers.String("uri", string(params.URI)), helpers.Error(err))
	}
}

// inScope reports whether a scan covered the document: it is below a workspace
// folder, or, with no folders, one of the documents scanned.
func (c *coordinator) inScope(path string) bool {
	if len(c.roots) == 0 {
		return true
	}
	return slices.ContainsFunc(c.roots, func(root string) bool { return within(root, path) })
}

// within reports whether path is root or below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(canonical(root), canonical(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// dedupeRoots removes the workspace folders contained in another, and repeats,
// so that no part of the workspace is scanned twice.
func dedupeRoots(roots []string) []string {
	var out []string
	for i, root := range roots {
		keep := true
		for j, other := range roots {
			if i == j {
				continue
			}
			if within(other, root) && (!within(root, other) || j < i) {
				keep = false // inside another root, or a repeat of an earlier one
				break
			}
		}
		if keep {
			out = append(out, filepath.Clean(root))
		}
	}
	return out
}

// canonical resolves symlinks, so that a document's path and the one a scan
// reports compare equal. A file that is gone is resolved through its directory.
func canonical(path string) string {
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	dir, base := filepath.Split(path)
	if dir == "" || filepath.Clean(dir) == path {
		return path
	}
	return filepath.Join(canonical(dir), base)
}

func canonicalKey(path string) string { return pathKey(canonical(path)) }
