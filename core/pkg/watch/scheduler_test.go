package watch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout only bounds how long a broken test waits; nothing passes by it.
const testTimeout = 10 * time.Second

const testDebounce = 500 * time.Millisecond

// fakeClock makes timers that fire when the test advances time and not before.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	// armed receives one value each time a timer is started or restarted, so
	// that a test knows the scheduler has seen a change and is debouncing it.
	armed chan struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(0, 0), armed: make(chan struct{}, 1024)}
}

type fakeTimer struct {
	clock    *fakeClock
	c        chan time.Time
	deadline time.Time
	active   bool
}

func (c *fakeClock) NewTimer(d time.Duration) timer {
	t := &fakeTimer{clock: c, c: make(chan time.Time, 1)}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	t.Reset(d)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	was := t.active
	t.active = true
	t.deadline = t.clock.now.Add(d)
	// A timer that is restarted holds no value from before, as time.Timer does.
	select {
	case <-t.c:
	default:
	}
	t.clock.mu.Unlock()
	t.clock.armed <- struct{}{}
	return was
}

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.active = false
	select {
	case <-t.c:
	default:
	}
	return was
}

// Advance moves time forward and fires the timers that fall due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if t.active && !t.deadline.After(c.now) {
			t.active = false
			select {
			case t.c <- c.now:
			default:
			}
		}
	}
}

// waitArmed waits until the scheduler has started or restarted a debounce n
// times: once for each change it has read. Time must not be advanced before it
// has read every change that was queued, or a debounce restarted by a later one
// would discard the expiry.
func (c *fakeClock) waitArmed(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-c.armed:
		case <-time.After(testTimeout):
			t.Fatalf("the scheduler started a debounce %d times, not %d", i, n)
		}
	}
}

// remaining is how long until the active timer fires, or false if none is active.
func (c *fakeClock) remaining() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.timers {
		if t.active {
			return t.deadline.Sub(c.now), true
		}
	}
	return 0, false
}

func (c *fakeClock) anyActive() bool {
	_, active := c.remaining()
	return active
}

// harness runs a Scheduler under test with scans that the test controls.
type harness struct {
	t       *testing.T
	clock   *fakeClock
	changes chan struct{}
	cancel  context.CancelFunc
	result  chan error

	scans    atomic.Int32 // scans started
	inFlight atomic.Int32
	maxSeen  atomic.Int32
	started  chan int      // the number of each scan as it starts
	release  chan struct{} // lets a blocked scan finish; nil lets scans finish at once
	errs     []error       // reported by OnError; read after Run returns
	scanErr  func(n int) error
}

// withScanErr makes scan n fail with fn(n).
func withScanErr(fn func(n int) error) func(*harness) {
	return func(h *harness) { h.scanErr = fn }
}

// newHarness starts the scheduler. A scan blocks until release gets a value
// when block is set, and returns at once otherwise. changesCap is the capacity
// of the changes channel: one, as a FileWatcher's is, unless a test says
// otherwise.
func newHarness(t *testing.T, block bool, changesCap int, options ...func(*harness)) *harness {
	t.Helper()
	h := &harness{
		t:       t,
		clock:   newFakeClock(),
		changes: make(chan struct{}, changesCap),
		result:  make(chan error, 1),
		started: make(chan int, 64),
	}
	if block {
		h.release = make(chan struct{})
	}
	for _, option := range options {
		option(h) // before the scheduler runs: it reads what they set
	}

	scan := func(ctx context.Context) error {
		n := h.scans.Add(1)
		now := h.inFlight.Add(1)
		for {
			peak := h.maxSeen.Load()
			if now <= peak || h.maxSeen.CompareAndSwap(peak, now) {
				break
			}
		}
		defer h.inFlight.Add(-1)
		h.started <- int(n)
		if h.release != nil {
			select {
			case <-h.release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if h.scanErr != nil {
			return h.scanErr(int(n))
		}
		return nil
	}

	s := NewScheduler(h.changes, scan, SchedulerOptions{
		Debounce: testDebounce,
		OnError:  func(err error) { h.errs = append(h.errs, err) },
		clock:    h.clock,
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	go func() { h.result <- s.Run(ctx) }()
	return h
}

// change signals a change the way a FileWatcher does: without ever waiting.
func (h *harness) change() {
	select {
	case h.changes <- struct{}{}:
	default:
	}
}

// waitStarted waits for scan n to start.
func (h *harness) waitStarted(n int) {
	h.t.Helper()
	select {
	case got := <-h.started:
		require.Equal(h.t, n, got, "scans started out of turn")
	case <-time.After(testTimeout):
		h.t.Fatalf("scan %d did not start", n)
	}
}

// finish cancels and waits for Run to return, and returns its error.
func (h *harness) finish() error {
	h.t.Helper()
	h.cancel()
	select {
	case err := <-h.result:
		return err
	case <-time.After(testTimeout):
		h.t.Fatal("Run did not return after cancellation")
		return nil
	}
}

func TestSchedulerScansOnceAtStartWithoutWaitingForChanges(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false, 1)

	h.waitStarted(1)
	assert.False(t, h.clock.anyActive(), "no debounce runs before there is a change")

	require.ErrorIs(t, h.finish(), context.Canceled)
	assert.EqualValues(t, 1, h.scans.Load(), "exactly the initial scan ran")
}

func TestSchedulerOneChangeIsOneScanAfterTheDebounce(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false, 1)
	h.waitStarted(1)

	h.change()
	h.clock.waitArmed(t, 1)
	remaining, active := h.clock.remaining()
	require.True(t, active)
	assert.Equal(t, testDebounce, remaining)

	// Not before the time is up.
	h.clock.Advance(testDebounce - time.Nanosecond)
	assert.EqualValues(t, 1, h.scans.Load(), "a scan started before the debounce was over")

	h.clock.Advance(time.Nanosecond)
	h.waitStarted(2)

	require.ErrorIs(t, h.finish(), context.Canceled)
	assert.EqualValues(t, 2, h.scans.Load())
}

func TestSchedulerBurstOfChangesIsOneScanFromTheLastOne(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false, 1)
	h.waitStarted(1)

	// Changes at 0, 100, 250 and 400 ms: each restarts the debounce.
	for _, gap := range []time.Duration{0, 100 * time.Millisecond, 150 * time.Millisecond, 150 * time.Millisecond} {
		h.clock.Advance(gap)
		h.change()
		h.clock.waitArmed(t, 1)
		remaining, _ := h.clock.remaining()
		assert.Equal(t, testDebounce, remaining, "the debounce was not restarted by the change")
	}
	assert.EqualValues(t, 1, h.scans.Load(), "a scan started during the burst")

	// 400 ms after the last change: still waiting.
	h.clock.Advance(testDebounce - time.Nanosecond)
	assert.EqualValues(t, 1, h.scans.Load())
	h.clock.Advance(time.Nanosecond)
	h.waitStarted(2)

	// And that was all of it.
	require.ErrorIs(t, h.finish(), context.Canceled)
	assert.EqualValues(t, 2, h.scans.Load(), "the burst made more than one scan")
}

func TestSchedulerChangesDuringAScanMakeExactlyOneFollowUp(t *testing.T) {
	t.Parallel()
	// A watcher's channel holds one signal; a larger one holds several, which the
	// scheduler must still turn into one scan.
	for _, capacity := range []int{1, 16} {
		capacity := capacity
		t.Run(fmt.Sprintf("changes channel capacity %d", capacity), func(t *testing.T) {
			t.Parallel()
			queued := func(changes int) int { return min(changes, capacity) }
			h := newHarness(t, true, capacity)
			h.waitStarted(1) // the initial scan is running, and blocked

			for i := 0; i < 10; i++ {
				h.change() // a watcher never waits for a scan
			}
			assert.False(t, h.clock.anyActive(), "a debounce started while a scan was running")

			h.release <- struct{}{}          // the scan ends
			h.clock.waitArmed(t, queued(10)) // the pending changes are found, and debounced
			assert.EqualValues(t, 1, h.scans.Load(), "the follow-up did not wait for the debounce")
			remaining, _ := h.clock.remaining()
			assert.Equal(t, testDebounce, remaining, "the follow-up is a full debounce after the scan")

			h.clock.Advance(testDebounce)
			h.waitStarted(2)

			// Changes during the follow-up are not lost either.
			h.change()
			h.change()
			h.release <- struct{}{}
			h.clock.waitArmed(t, queued(2))
			h.clock.Advance(testDebounce)
			h.waitStarted(3)
			h.release <- struct{}{}

			// Nothing is left over: no change is waiting, so no scan follows.
			require.ErrorIs(t, h.finish(), context.Canceled)
			assert.EqualValues(t, 3, h.scans.Load(), "more scans than there were stretches of changes")
		})
	}
}

func TestSchedulerNeverRunsTwoScansAtOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t, true, 1)
	h.waitStarted(1)

	for scan := 2; scan <= 6; scan++ {
		// Changes arrive while the previous scan runs, and while it ends.
		h.change()
		h.release <- struct{}{}
		h.clock.waitArmed(t, 1)
		h.change() // during the debounce: it restarts
		h.clock.waitArmed(t, 1)
		h.clock.Advance(testDebounce)
		h.waitStarted(scan)
	}
	h.release <- struct{}{}

	require.ErrorIs(t, h.finish(), context.Canceled)
	assert.EqualValues(t, 1, h.maxSeen.Load(), "scans overlapped")
	assert.EqualValues(t, 0, h.inFlight.Load())
}

func TestSchedulerFailedScansAreReportedAndWatchingGoesOn(t *testing.T) {
	t.Parallel()
	boom := errors.New("initial scan failed")
	bang := errors.New("follow-up failed")
	h := newHarness(t, false, 1, withScanErr(func(n int) error {
		switch n {
		case 1:
			return boom
		case 3:
			return bang
		}
		return nil
	}))

	h.waitStarted(1) // fails
	for scan := 2; scan <= 4; scan++ {
		h.change()
		h.clock.waitArmed(t, 1)
		h.clock.Advance(testDebounce)
		h.waitStarted(scan)
	}

	require.ErrorIs(t, h.finish(), context.Canceled)
	// Scans 2 and 4 succeeded after failures: nothing was left in a bad state.
	assert.EqualValues(t, 4, h.scans.Load())
	assert.Equal(t, []error{boom, bang}, h.errs, "errors are reported once each, in order")
}

func TestSchedulerCancellation(t *testing.T) {
	t.Parallel()

	t.Run("while idle", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, false, 1)
		h.waitStarted(1)
		require.ErrorIs(t, h.finish(), context.Canceled)
		assert.EqualValues(t, 1, h.scans.Load())
	})

	t.Run("while debouncing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, false, 1)
		h.waitStarted(1)
		h.change()
		h.clock.waitArmed(t, 1)
		require.True(t, h.clock.anyActive())

		require.ErrorIs(t, h.finish(), context.Canceled)
		assert.False(t, h.clock.anyActive(), "the debounce timer was left running")
		h.clock.Advance(time.Hour)
		assert.EqualValues(t, 1, h.scans.Load(), "a scan started after cancellation")
	})

	t.Run("during a scan", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, true, 1)
		h.waitStarted(1) // blocked until its context ends
		h.change()

		// The scan returns the context's error, as it is asked to; that is not a
		// failure to report, and nothing follows it.
		require.ErrorIs(t, h.finish(), context.Canceled)
		assert.Empty(t, h.errs)
		assert.EqualValues(t, 1, h.scans.Load())
	})

	t.Run("before it starts", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var scans atomic.Int32
		s := NewScheduler(make(chan struct{}), func(context.Context) error { scans.Add(1); return nil }, SchedulerOptions{})
		require.ErrorIs(t, s.Run(ctx), context.Canceled)
		assert.Zero(t, scans.Load(), "a scan ran for a context that was already done")
	})
}

func TestSchedulerEndsWhenTheChangesChannelIsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, false, 1)
	h.waitStarted(1)

	close(h.changes)
	select {
	case err := <-h.result:
		assert.ErrorIs(t, err, ErrChangesClosed)
	case <-time.After(testTimeout):
		t.Fatal("Run did not return when the changes channel was closed")
	}
}

func TestSchedulerRefusesASecondRun(t *testing.T) {
	t.Parallel()
	// A second Run on the same scheduler would be a second scan at once.
	s := NewScheduler(make(chan struct{}), func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, SchedulerOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	running := make(chan error, 1)
	go func() { running <- s.Run(ctx) }()
	require.Eventually(t, s.running.Load, testTimeout, time.Millisecond)

	assert.ErrorIs(t, s.Run(context.Background()), ErrSchedulerRunning)

	cancel()
	require.ErrorIs(t, <-running, context.Canceled)
	assert.False(t, s.running.Load(), "a finished scheduler is left marked as running")
}

func TestSchedulerDebounceDefault(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 500*time.Millisecond, DefaultDebounce)
	for _, d := range []time.Duration{0, -time.Second} {
		s := NewScheduler(nil, nil, SchedulerOptions{Debounce: d})
		assert.Equal(t, DefaultDebounce, s.debounce)
	}
	assert.Equal(t, time.Second, NewScheduler(nil, nil, SchedulerOptions{Debounce: time.Second}).debounce)
}

// A watcher that stops with the shared context closes its channel at the same
// moment the context ends. The context is the reason, so it is what Run returns,
// every time: both can be ready, and select would pick at random.
func TestSchedulerReportsTheContextWhenItAndTheChannelEndTogether(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		changes := make(chan struct{}, 1)
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		s := NewScheduler(changes, func(ctx context.Context) error {
			close(ready)
			<-ctx.Done() // held until the context ends, as a scan is
			return ctx.Err()
		}, SchedulerOptions{})
		result := make(chan error, 1)
		go func() { result <- s.Run(ctx) }()

		<-ready
		cancel()
		close(changes) // both are done by the time the scan returns

		select {
		case err := <-result:
			require.ErrorIs(t, err, context.Canceled, "round %d", i)
		case <-time.After(testTimeout):
			t.Fatal("Run did not return")
		}
	}
}
