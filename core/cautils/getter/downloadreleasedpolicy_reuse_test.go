package getter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/regolibrary/v2/gitregostore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// release serves the smallest release a store accepts, under the name of one
// framework, and lets a test count the requests made for each of its files, make
// a file fail, and hold a file back until the test lets it go.
type release struct {
	*httptest.Server
	framework string

	mu       sync.Mutex
	requests map[string]int
	failing  map[string]bool
	gates    map[string]chan struct{}
	arrivals map[string]chan struct{}
	aborted  map[string]int
	// badSignature makes the release serve a checksum manifest whose signature
	// does not verify, which the store reports as ErrChecksumVerification.
	badSignature bool
}

func newRelease(t *testing.T, framework string) *release {
	t.Helper()
	r := &release{
		framework: framework,
		requests:  map[string]int{},
		failing:   map[string]bool{},
		gates:     map[string]chan struct{}{},
		arrivals:  map[string]chan struct{}{},
		aborted:   map[string]int{},
	}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.Close)
	return r
}

func (r *release) serve(w http.ResponseWriter, req *http.Request) {
	file := req.URL.Path[len("/download/"):]
	r.mu.Lock()
	r.requests[file]++
	gate := r.gates[file]
	select {
	case <-r.arrival(file):
	default:
		close(r.arrival(file))
	}
	r.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-req.Context().Done():
			// the client ended the request: it was not left waiting
			r.mu.Lock()
			r.aborted[file]++
			r.mu.Unlock()
			return
		}
	}
	r.mu.Lock()
	fail := r.failing[file] // read once the request is let go, so a test can fail a held one
	r.mu.Unlock()
	if fail {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	switch file {
	case "checksums.txt", "checksums.sigstore.json":
		r.mu.Lock()
		bad := r.badSignature
		r.mu.Unlock()
		if bad {
			fmt.Fprint(w, "not a valid signature")
			return
		}
		http.NotFound(w, req) // an unsigned release: the store takes the files as they are
	case "frameworks":
		fmt.Fprintf(w, `[{"name":%q,"typeTags":["compliance"]}]`, r.framework)
	case "controls":
		fmt.Fprint(w, `[{"controlID":"C-0001","name":"first"}]`)
	case "default_config_inputs":
		fmt.Fprint(w, `{"settings":{"postureControlInputs":{"k":["v"]}}}`)
	case "FWName_CID_CName", "ControlID_RuleName":
		fmt.Fprint(w, "a,b\n")
	case "security_frameworks", "attack_tracks", "rules", "exceptions":
		fmt.Fprint(w, `[]`)
	default:
		http.NotFound(w, req)
	}
}

// arrival is closed when the first request for file reaches the server. The
// caller holds r.mu.
func (r *release) arrival(file string) chan struct{} {
	if r.arrivals[file] == nil {
		r.arrivals[file] = make(chan struct{})
	}
	return r.arrivals[file]
}

// arrived returns a channel that is closed once a request for file has reached
// the server, which is how a test knows that the request is the one in flight.
func (r *release) arrived(file string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.arrival(file)
}

// abortedRequests counts the requests for file that the client ended before the
// server answered.
func (r *release) abortedRequests(file string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted[file]
}

func (r *release) count(file string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[file]
}

func (r *release) fail(file string, failing bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failing[file] = failing
}

// hold keeps the requests for file waiting until the returned function is called.
func (r *release) hold(file string) (open func()) {
	gate := make(chan struct{})
	r.mu.Lock()
	r.gates[file] = gate
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.gates, file)
			r.mu.Unlock()
			close(gate)
		})
	}
}

func (r *release) store() *DownloadReleasedPolicy {
	p := NewDownloadReleasedPolicyWithVersion("")
	p.gs.URL = r.URL + "/download"
	return p
}

// waitIdle waits for the store's download to end, which is how a test knows that
// nothing is left running behind it.
func waitIdle(t *testing.T, p *DownloadReleasedPolicy) {
	t.Helper()
	require.Eventually(t, func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.loading == nil
	}, 10*time.Second, 5*time.Millisecond, "a download is still running")
}

// holdsNone reports whether the getters see no part of a release.
func holdsNone(p *DownloadReleasedPolicy) error {
	if _, err := p.GetFramework("nsa"); err == nil {
		return errors.New("a framework is visible")
	}
	if names, err := p.ListFrameworks(); err == nil && len(names) != 0 {
		return fmt.Errorf("frameworks are listed: %v", names)
	}
	if _, err := p.GetControlsInputs(context.Background(), ""); err == nil {
		return errors.New("control inputs are visible")
	}
	if controls, err := p.store().GetOPAControls(); err == nil && len(controls) != 0 {
		return errors.New("controls are visible")
	}
	return nil
}

// holdsAll reports whether the getters see the whole of the release.
func holdsAll(p *DownloadReleasedPolicy, framework string) error {
	if fw, err := p.GetFramework(framework); err != nil || fw.Name != framework {
		return fmt.Errorf("the framework is missing: %v", err)
	}
	if inputs, err := p.GetControlsInputs(context.Background(), ""); err != nil || len(inputs["k"]) != 1 {
		return fmt.Errorf("the control inputs are missing: %v", err)
	}
	if controls, err := p.store().GetOPAControls(); err != nil || len(controls) != 1 {
		return fmt.Errorf("the controls are missing: %v", err)
	}
	return nil
}

// A store that scans share downloads the release once, however many scans read
// it, and serves each of them from memory.
func TestSharedStoreDownloadsTheReleaseOnce(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()

	for scan := 1; scan <= 4; scan++ {
		fallback, err := p.SetRegoObjectsWithFallback()
		require.NoError(t, err, "scan %d", scan)
		require.False(t, fallback, "scan %d", scan)
		require.NoError(t, holdsAll(p, "nsa"), "scan %d", scan)
	}

	assert.Equal(t, 1, r.count("frameworks"), "the release was downloaded once for four scans")
	assert.Equal(t, 1, r.count("controls"))
	assert.Equal(t, 1, r.count("default_config_inputs"))
	assert.Equal(t, 1, r.count("checksums.txt"))
}

// Scans that start together, before anything is downloaded, wait for the one
// download and share it. Run with -race this also checks that sharing the store
// between scans is free of data races.
func TestConcurrentFirstLoadsDownloadTheReleaseOnce(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	open := r.hold("controls") // keeps the download open until every scan is waiting
	defer open()

	const scans = 16
	var started, finished sync.WaitGroup
	errs := make([]error, scans)
	for i := 0; i < scans; i++ {
		started.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			started.Done()
			fallback, err := p.SetRegoObjectsWithFallbackContext(t.Context())
			if err == nil && fallback {
				err = errors.New("asked to fall back to the cache")
			}
			if err == nil {
				err = holdsAll(p, "nsa")
			}
			errs[i] = err
		}()
	}
	started.Wait()
	require.Eventually(t, func() bool { return r.count("controls") >= 1 }, 10*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let the scans that are going to join the download do so
	open()
	finished.Wait()

	for i, err := range errs {
		require.NoError(t, err, "scan %d", i)
	}
	assert.Equal(t, 1, r.count("checksums.txt"), "sixteen scans started together made one download")
	assert.Equal(t, 1, r.count("frameworks"))
	assert.Equal(t, 1, r.count("controls"))
	waitIdle(t, p)
}

// The failure the store used to have. A download that failed after some of the
// files had arrived left them in the store the getters read, so the next scan
// saw frameworks without controls. Which files arrive before the failure depends
// on the order they are asked for, so this repeats until that cannot be luck.
func TestFailedDownloadLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	for attempt := 0; attempt < 24; attempt++ {
		r := newRelease(t, "nsa")
		r.fail("controls", true)
		p := r.store()

		fallback, err := p.SetRegoObjectsWithFallback()
		require.NoError(t, err, "an unpinned release that fails to download asks to fall back to the cache")
		require.True(t, fallback)

		require.NoError(t, holdsNone(p), "attempt %d: the getters saw part of the release", attempt)
		waitIdle(t, p)
	}
}

// A failed download is not remembered. The next scan downloads again, all of it,
// and then the release is kept.
func TestFailedFirstLoadIsRetriedAndThenKept(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	r.fail("controls", true)
	p := r.store()

	fallback, err := p.SetRegoObjectsWithFallback()
	require.NoError(t, err)
	require.True(t, fallback)
	require.NoError(t, holdsNone(p))
	require.Equal(t, 1, r.count("checksums.txt"))

	r.fail("controls", false)
	fallback, err = p.SetRegoObjectsWithFallback()
	require.NoError(t, err)
	require.False(t, fallback)
	require.NoError(t, holdsAll(p, "nsa"))
	assert.Equal(t, 2, r.count("checksums.txt"), "the second scan downloaded the release again")

	fallback, err = p.SetRegoObjectsWithFallback()
	require.NoError(t, err)
	require.False(t, fallback)
	assert.Equal(t, 2, r.count("checksums.txt"), "and the third did not")
}

// Scans that are waiting on a download that fails all get its failure, and make
// no download of their own: a server that is down is asked once, not once per
// scan.
func TestWaitersOfAFailedDownloadShareItsFailure(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	r.fail("controls", true)
	open := r.hold("controls")
	defer open()
	p := r.store()

	const scans = 8
	var finished sync.WaitGroup
	fallbacks := make([]bool, scans)
	errs := make([]error, scans)
	for i := 0; i < scans; i++ {
		finished.Add(1)
		go func() {
			defer finished.Done()
			fallbacks[i], errs[i] = p.SetRegoObjectsWithFallbackContext(t.Context())
		}()
	}
	// Every scan has joined the download before it is let go: one that came
	// after it failed would start a download of its own.
	waitersOf(t, p, scans)
	open()
	finished.Wait()

	for i := range errs {
		require.NoError(t, errs[i], "scan %d", i)
		assert.True(t, fallbacks[i], "scan %d is asked to fall back to the cache", i)
	}
	assert.Equal(t, 1, r.count("checksums.txt"), "eight scans waiting on one download asked the server once")
	waitIdle(t, p)
}

// While the release is downloading, and while a retry of a failed download is,
// readers see none of it; once it is complete they see all of it. They never see
// a store with the frameworks and without the controls.
func TestReadersNeverSeeAPartialRelease(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	r.fail("controls", true)
	p := r.store()
	fallback, err := p.SetRegoObjectsWithFallback()
	require.NoError(t, err)
	require.True(t, fallback)

	// The retry: every file but the controls arrives at once, and the controls are
	// held back, which is the window in which the old store was half full.
	r.fail("controls", false)
	open := r.hold("controls")
	defer open()

	var (
		stop     = make(chan struct{})
		readers  sync.WaitGroup
		observed atomic.Int64
		partial  atomic.Value // the first partial view a reader saw
	)
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// A reader sees all of the release or none of it.
				if holdsNone(p) != nil && holdsAll(p, "nsa") != nil {
					partial.CompareAndSwap(nil, "a reader saw a part of the release")
				}
				observed.Add(1)
			}
		}()
	}

	retried := make(chan error, 1)
	go func() {
		_, err := p.SetRegoObjectsWithFallbackContext(t.Context())
		retried <- err
	}()
	require.Eventually(t, func() bool { return r.count("controls") >= 2 }, 10*time.Second, 5*time.Millisecond, "the retry reached the controls")
	before := observed.Load()
	require.Eventually(t, func() bool { return observed.Load() > before+200 }, 10*time.Second, time.Millisecond, "readers ran while the retry was held open")
	require.NoError(t, holdsNone(p), "the retry has not finished, and nothing of it is visible")

	open()
	require.NoError(t, <-retried)
	require.NoError(t, holdsAll(p, "nsa"))
	close(stop)
	readers.Wait()

	assert.Nil(t, partial.Load())
	waitIdle(t, p)
}

// Stores of different releases keep to their own: a scan of one release is never
// served the files of another.
func TestStoresOfDifferentReleasesDoNotShareData(t *testing.T) {
	t.Parallel()
	latest, pinned := newRelease(t, "latest-framework"), newRelease(t, "pinned-framework")
	a := latest.store()
	b := NewDownloadReleasedPolicyWithVersion("v2.0.301")
	b.gs.URL = pinned.URL + "/download"

	for _, p := range []*DownloadReleasedPolicy{a, b} {
		fallback, err := p.SetRegoObjectsWithFallback()
		require.NoError(t, err)
		require.False(t, fallback)
	}

	require.NoError(t, holdsAll(a, "latest-framework"))
	require.NoError(t, holdsAll(b, "pinned-framework"))
	_, err := a.GetFramework("pinned-framework")
	assert.Error(t, err, "the latest release does not hold the pinned release's framework")
	_, err = b.GetFramework("latest-framework")
	assert.Error(t, err, "the pinned release does not hold the latest release's framework")
	assert.NotEqual(t, a.CacheSource(), b.CacheSource())
	assert.Equal(t, 1, pinned.count("controls"), "each release was downloaded once")
	assert.Equal(t, 1, latest.count("controls"))
}

// A pinned release that fails to download is a hard error that names the release,
// and the cause stays reachable through it.
func TestPinnedReleaseFailureIsAnErrorThatKeepsItsCause(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	r.fail("controls", true)
	p := NewDownloadReleasedPolicyWithVersion("v2.0.301")
	p.gs.URL = r.URL + "/download"

	fallback, err := p.SetRegoObjectsWithFallback()

	require.Error(t, err)
	assert.False(t, fallback, "a pinned release does not fall back to another one")
	assert.Contains(t, err.Error(), "v2.0.301")
	assert.NoError(t, holdsNone(p))
	waitIdle(t, p)
}

// A scan that is cancelled stops waiting for the download and is told why, not
// asked to fall back to the cache. The download it was waiting for goes on, and
// the next scan joins it instead of starting another.
func TestCancelledScanStopsWaitingAndTheDownloadIsKept(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	open := r.hold("controls")
	defer open()
	p := r.store()

	ctx, cancel := context.WithCancel(t.Context())
	cancelled := make(chan error, 1)
	var fallback atomic.Bool
	go func() {
		fb, err := p.SetRegoObjectsWithFallbackContext(ctx)
		fallback.Store(fb)
		cancelled <- err
	}()
	require.Eventually(t, func() bool { return r.count("controls") >= 1 }, 10*time.Second, 5*time.Millisecond)

	cancel()
	select {
	case err := <-cancelled:
		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, fallback.Load(), "a cancelled scan is not asked to carry on with the cache")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled scan is still waiting for the download")
	}
	require.NoError(t, holdsNone(p))

	joined := make(chan error, 1)
	go func() {
		fb, err := p.SetRegoObjectsWithFallbackContext(t.Context())
		if err == nil && fb {
			err = errors.New("asked to fall back")
		}
		joined <- err
	}()
	time.Sleep(50 * time.Millisecond)
	open()
	require.NoError(t, <-joined)

	require.NoError(t, holdsAll(p, "nsa"))
	assert.Equal(t, 1, r.count("checksums.txt"), "the next scan joined the download that was running")
	waitIdle(t, p)
}

// A scan whose context has ended before it asks does not start a download.
func TestEndedContextDoesNotStartADownload(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	fallback, err := p.SetRegoObjectsWithFallbackContext(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, fallback)
	assert.Zero(t, r.count("checksums.txt"))
	assert.NoError(t, holdsNone(p))
}

// A store that already holds the release, as the tests that fill one by hand
// make it, is used as it is, with no download.
func TestStoreWithTheReleaseAlreadyLoadedIsNotDownloadedAgain(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	fallback, err := p.SetRegoObjectsWithFallback()
	require.NoError(t, err)
	require.False(t, fallback)
	loadedStore := p.store()

	for i := 0; i < 3; i++ {
		_, err := p.SetRegoObjectsWithFallback()
		require.NoError(t, err)
	}

	assert.Same(t, loadedStore, p.store(), "the store was not replaced")
	assert.Equal(t, 1, r.count("checksums.txt"))
}

// fetchesInProgress counts the goroutines that are inside a store's download.
func fetchesInProgress() int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "gitregostore.(*GitRegoStore).SetRegoObjects")
}

// endsAt makes the store's download run under a context that the test ends.
func endsAt(p *DownloadReleasedPolicy) (end func()) {
	ctx, cancel := context.WithCancel(context.Background())
	p.downloadContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	return cancel
}

func isLoading(p *DownloadReleasedPolicy) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loading != nil
}

// waitersOf waits until n callers have joined the download in progress.
func waitersOf(t *testing.T, p *DownloadReleasedPolicy, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.loading != nil && p.loading.waiters == n
	}, 10*time.Second, time.Millisecond, "%d callers did not join the download", n)
}

// The store keeps the client it makes its requests with to itself, and the
// download's time limit works through it. A version of the store that changes
// that fails here, and not by letting a request run on unbounded.
func TestStoreRequestsCanBeBound(t *testing.T) {
	t.Parallel()
	assert.True(t, bindRequests(NewDownloadReleasedPolicy().gs, t.Context()))
}

// A server that takes the request and never answers must not hold the download:
// when its time is up the request itself is ended, which the server sees as the
// client going away, and nothing of the download is left running. The store is
// free for another, nothing was published, and the retry loads the release.
// Not parallel: it counts the fetches running in the process.
func TestStalledRequestIsEndedWhenTheDownloadTimesOut(t *testing.T) {
	before := fetchesInProgress()
	r := newRelease(t, "nsa")
	p := r.store()
	end := endsAt(p)
	open := r.hold("controls")
	defer open()

	result := make(chan error, 1)
	go func() { result <- p.SetRegoObjectsContext(t.Context()) }()
	<-r.arrived("controls")
	assert.Equal(t, 0, r.abortedRequests("controls"), "the request was ended before its time was up")
	end()

	require.ErrorIs(t, <-result, errDownloadTimedOut)
	assert.False(t, isLoading(p), "the timed-out download still holds the store")
	require.NoError(t, holdsNone(p))

	// The gate is still shut: only the client ending the request lets the handler go.
	require.Eventually(t, func() bool { return r.abortedRequests("controls") == 1 }, 10*time.Second, time.Millisecond,
		"the request was left open")
	require.Eventually(t, func() bool { return fetchesInProgress() <= before }, 10*time.Second, time.Millisecond,
		"the download's fetch did not end")
	require.NoError(t, holdsNone(p), "a timed-out download published the release")

	p.downloadContext = nil
	open()
	require.NoError(t, p.SetRegoObjectsContext(t.Context()))
	require.NoError(t, holdsAll(p, "nsa"))
	assert.Equal(t, 2, r.count("controls"), "the retry downloaded the release again")
}

// The limit is also a real one: with no test in charge of it, a download that
// stalls ends at it, for a caller whose own context does not.
func TestStalledDownloadEndsAtItsTimeLimit(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	p.downloadTimeout = 200 * time.Millisecond
	open := r.hold("controls")
	defer open()

	require.ErrorIs(t, p.SetRegoObjectsContext(t.Context()), errDownloadTimedOut)
	assert.False(t, isLoading(p))
	require.NoError(t, holdsNone(p))

	p.downloadTimeout = 0
	open()
	require.NoError(t, p.SetRegoObjectsContext(t.Context()))
	require.NoError(t, holdsAll(p, "nsa"))
}

// Scans that wait together for a stalled download share its timeout. The
// download is not allowed to time out until every scan has joined it, so each
// gets the one outcome of the one download the server was asked for.
func TestWaitersOfAStalledDownloadShareItsTimeout(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	end := endsAt(p)
	open := r.hold("controls")
	defer open()

	const scans = 8
	errs := make([]error, scans)
	var wg sync.WaitGroup
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = p.SetRegoObjectsContext(t.Context())
		}()
	}
	waitersOf(t, p, scans)
	<-r.arrived("controls")
	end()
	wg.Wait()

	for i, err := range errs {
		require.ErrorIs(t, err, errDownloadTimedOut, "scan %d", i)
	}
	assert.Equal(t, 1, r.count("controls"), "the scans did not share one download")
	assert.False(t, isLoading(p))

	p.downloadContext = nil
	open()
	require.NoError(t, p.SetRegoObjectsContext(t.Context()))
	require.NoError(t, holdsAll(p, "nsa"))
	assert.Equal(t, 2, r.count("controls"))
}

// A scan that gives up while the download is in flight stops waiting at once
// and leaves the download running for the others, which is not duplicated. When
// that download then fails the store is free and the next scan retries.
func TestCancelledWaiterLeavesTheDownloadAndTheStoreRecoverable(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := r.store()
	open := r.hold("controls")
	defer open()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- p.SetRegoObjectsContext(ctx) }()
	<-r.arrived("controls")
	cancel()

	require.ErrorIs(t, <-result, context.Canceled)
	assert.True(t, isLoading(p), "the download others may wait for was dropped")
	assert.Equal(t, 0, r.abortedRequests("controls"), "a waiter leaving ended the request")

	// The download then fails, and the store can be used again.
	r.fail("controls", true)
	open()
	waitIdle(t, p)
	require.NoError(t, holdsNone(p))
	r.fail("controls", false)
	require.NoError(t, p.SetRegoObjectsContext(t.Context()))
	require.NoError(t, holdsAll(p, "nsa"))
	assert.Equal(t, 2, r.count("controls"))
}

// A pinned release says which one timed out, and the cause can still be found.
func TestPinnedReleaseTimeoutKeepsItsCause(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	p := NewDownloadReleasedPolicyWithVersion("v2.0.301")
	p.gs.URL = r.URL + "/download"
	end := endsAt(p)
	open := r.hold("controls")
	defer open()

	result := make(chan error, 1)
	go func() { result <- p.SetRegoObjectsContext(t.Context()) }()
	<-r.arrived("controls")
	end()

	err := <-result
	require.ErrorIs(t, err, errDownloadTimedOut)
	assert.Contains(t, err.Error(), `"v2.0.301"`)
}

// endsLate is a context that reads as live until the test ends it, and whose
// Done channel never closes. It puts a download at the point where its fetch has
// already returned an error and the download's time is found to be up, which a
// real deadline cannot be made to hit on purpose.
type endsLate struct {
	context.Context
	ended atomic.Bool
}

func (c *endsLate) Err() error {
	if c.ended.Load() {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

// A download whose checksum verification failed as its time ran out is still a
// checksum failure: the error keeps both causes, and the unpinned store does not
// fall back to the cache, which would serve policies that were never verified
// against the release (#3791).
func TestChecksumFailureAtTheTimeLimitStaysAHardFailure(t *testing.T) {
	t.Parallel()
	r := newRelease(t, "nsa")
	r.mu.Lock()
	r.badSignature = true
	r.mu.Unlock()
	p := r.store()
	ctx := &endsLate{Context: context.Background()}
	p.downloadContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	open := r.hold("checksums.sigstore.json")
	defer open()

	type outcome struct {
		fallback bool
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		fallback, err := p.SetRegoObjectsWithFallbackContext(t.Context())
		result <- outcome{fallback, err}
	}()
	// The signature is requested once the manifest has arrived. The time is up
	// while it is held back, and the response then fails verification.
	<-r.arrived("checksums.sigstore.json")
	ctx.ended.Store(true)
	open()

	got := <-result
	require.Error(t, got.err)
	assert.ErrorIs(t, got.err, gitregostore.ErrChecksumVerification, "the checksum failure was turned into text")
	assert.ErrorIs(t, got.err, errDownloadTimedOut, "the timeout was lost")
	assert.False(t, got.fallback, "a checksum failure must not fall back to the cache")
	assert.NoError(t, holdsNone(p))
	waitIdle(t, p)
}

// pastEntry is a context that is live when a caller enters the wait for a
// download and ended by the time the wait begins, and whose Done channel is
// already closed. A caller that stops at the same moment as the download it
// waits for is then deterministic, with both ready, not left to timing.
type pastEntry struct {
	context.Context
	err   error
	calls atomic.Int32
}

var closedChan = func() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

func (c *pastEntry) Done() <-chan struct{} { return closedChan }

func (c *pastEntry) Err() error {
	if c.calls.Add(1) == 1 {
		return nil // the check on entry
	}
	return c.err
}

// timedOutLoad puts p in the middle of a download that has just timed out.
func timedOutLoad(p *DownloadReleasedPolicy) {
	done := make(chan struct{})
	close(done)
	p.mu.Lock()
	p.loading = &releaseLoad{done: done, err: errDownloadTimedOut}
	p.mu.Unlock()
}

// A caller that has been stopped is told so, also when the download it waited
// for timed out at the same moment: select picks at random among ready cases, so
// this is repeated enough for a version that does not give the caller priority
// to be found.
func TestStoppedCallerGetsItsOwnErrorOverTheDownloadsTimeout(t *testing.T) {
	t.Parallel()
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			for i := 0; i < 64; i++ {
				p := NewDownloadReleasedPolicyWithVersion("")
				timedOutLoad(p)

				err := p.SetRegoObjectsContext(&pastEntry{Context: context.Background(), err: want})

				require.ErrorIs(t, err, want, "round %d", i)
				assert.NotErrorIs(t, err, errDownloadTimedOut, "round %d", i)
			}
		})
	}
}

// A stopped caller is not asked to fall back to the cache, whatever the
// download it waited for ended with.
func TestStoppedCallerIsNotAskedToFallBackAfterATimeout(t *testing.T) {
	t.Parallel()
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			for i := 0; i < 64; i++ {
				p := NewDownloadReleasedPolicyWithVersion("")
				timedOutLoad(p)

				fallback, err := p.SetRegoObjectsWithFallbackContext(&pastEntry{Context: context.Background(), err: want})

				require.ErrorIs(t, err, want, "round %d", i)
				assert.False(t, fallback, "round %d: a stopped scan was asked to fall back to the cache", i)
			}
		})
	}
}

// A caller that has not been stopped still gets the download's timeout, and an
// unpinned store still falls back to the cache for it, as for any download that
// fails; a pinned one reports the failure.
func TestActiveCallerStillGetsTheTimeoutAndItsFallback(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"", "v2.0.301"} {
		t.Run("version "+version, func(t *testing.T) {
			r := newRelease(t, "nsa")
			p := NewDownloadReleasedPolicyWithVersion(version)
			p.gs.URL = r.URL + "/download"
			end := endsAt(p)
			open := r.hold("controls")
			defer open()

			type outcome struct {
				fallback bool
				err      error
			}
			result := make(chan outcome, 1)
			go func() {
				fallback, err := p.SetRegoObjectsWithFallbackContext(t.Context())
				result <- outcome{fallback, err}
			}()
			<-r.arrived("controls")
			end()

			got := <-result
			if version == "" {
				assert.NoError(t, got.err)
				assert.True(t, got.fallback, "an unpinned store falls back to the cache when the download times out")
			} else {
				require.ErrorIs(t, got.err, errDownloadTimedOut)
				assert.False(t, got.fallback)
			}
			waitIdle(t, p)
		})
	}
}

// When the download's time is up while a fetch that failed is already waiting to
// be taken, the outcome keeps that failure beside the timeout. select picks at
// random when both are ready, so the timeout branch is exercised here directly,
// with the fetch's result already in place and the time up.
func TestTimedOutDownloadKeepsAFetchFailureThatIsAlreadyThere(t *testing.T) {
	t.Parallel()
	checksum := fmt.Errorf("%w: error verifying checksums.txt", gitregostore.ErrChecksumVerification)
	fetched := make(chan error, 1)
	fetched <- checksum

	err := timedOutDownload(fetched)

	require.Error(t, err)
	assert.ErrorIs(t, err, errDownloadTimedOut, "the timeout was lost")
	assert.ErrorIs(t, err, gitregostore.ErrChecksumVerification, "the checksum failure was lost")
	assert.ErrorIs(t, err, checksum)
	assert.Empty(t, fetched, "the result was left in the channel")
}

// With no result to take the outcome is the timeout alone, and getting it does
// not wait for a fetch that is still running. A fetch that had succeeded is not
// an outcome either: a download that timed out publishes nothing.
func TestTimedOutDownloadWithoutAFailedFetchIsTheTimeout(t *testing.T) {
	t.Parallel()
	t.Run("fetch still running", func(t *testing.T) {
		running := make(chan error) // nothing is ever sent: a read that waited would hang
		assert.Equal(t, errDownloadTimedOut, timedOutDownload(running))
	})
	t.Run("fetch succeeded", func(t *testing.T) {
		done := make(chan error, 1)
		done <- nil
		assert.Equal(t, errDownloadTimedOut, timedOutDownload(done))
	})
}

// A checksum failure that comes with the timeout is still a hard failure for an
// unpinned store: it is not asked to fall back to the cache (#3791). Any other
// failure that comes with it is as it was, and is asked to.
func TestTimedOutDownloadChecksumFailureIsNotAskedToFallBack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		failure      error
		wantFallback bool
	}{
		{"checksum failure", fmt.Errorf("%w: error verifying checksums.txt", gitregostore.ErrChecksumVerification), false},
		{"other failure", errors.New("connection reset"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewDownloadReleasedPolicyWithVersion("")
			fetched := make(chan error, 1)
			fetched <- tt.failure
			done := make(chan struct{})
			close(done)
			p.mu.Lock()
			p.loading = &releaseLoad{done: done, err: timedOutDownload(fetched)}
			p.mu.Unlock()

			fallback, err := p.SetRegoObjectsWithFallbackContext(t.Context())

			assert.Equal(t, tt.wantFallback, fallback)
			if tt.wantFallback {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, gitregostore.ErrChecksumVerification)
			assert.ErrorIs(t, err, errDownloadTimedOut)
		})
	}
}
