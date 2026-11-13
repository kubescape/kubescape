package watch

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// DefaultDebounce is how long a Scheduler waits after the last change before it
// scans again, when no other time is configured.
const DefaultDebounce = 500 * time.Millisecond

var (
	// ErrChangesClosed is returned by Run when the channel it was given to
	// receive changes on is closed while its context is still live. That is a
	// watcher that stopped, and the watcher says why (FileWatcher.Err).
	ErrChangesClosed = errors.New("watch: the change channel was closed")

	// ErrSchedulerRunning is returned by Run when it is already running, which
	// would otherwise allow two scans at once.
	ErrSchedulerRunning = errors.New("watch: the scheduler is already running")
)

// timer is the part of time.Timer a Scheduler uses.
type timer interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

// clock makes timers, so that a test can decide when time passes.
type clock interface {
	NewTimer(d time.Duration) timer
}

type realClock struct{}

func (realClock) NewTimer(d time.Duration) timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }

// SchedulerOptions configures a Scheduler.
type SchedulerOptions struct {
	// Debounce is how long to wait after the last change before scanning. Zero
	// or less selects DefaultDebounce.
	Debounce time.Duration

	// OnError, when set, receives the error of every scan that fails, except a
	// scan that was cut short because the scheduler's context ended. It is called
	// on the scheduler's goroutine, between scans.
	OnError func(error)

	clock clock // real time unless a test sets one
}

// Scheduler runs a scan once when it starts, and again after changes, one scan
// at a time. It knows nothing of files or of what a scan is: it is given a
// channel on which a change is signalled, and a function that scans.
//
// Its behaviour, in terms of what it is doing:
//
//   - Idle: nothing is pending. A signal on the changes channel starts the
//     debounce.
//   - Debouncing: a timer is running. Each further signal restarts it, so a
//     burst of changes ends in one scan, Debounce after the last of them. When
//     it expires the scan starts.
//   - Scanning: the scan function is running, on the goroutine that called Run.
//     The changes channel is not read meanwhile, so what is signalled during a
//     scan stays in it. With a channel of capacity one that is sent to without
//     blocking, as a FileWatcher's is, any number of changes leave one signal.
//     When the scan ends the next read finds it and starts a debounce: exactly
//     one further scan follows, Debounce after the first one ended, and changes
//     during that scan are held the same way. No change is lost, and no change
//     makes more than one scan.
//
// Scans are sequential because there is nothing else to run them: the scan
// function is only ever called from Run's goroutine, which does nothing else
// while it runs. No goroutines are started, so there is none to leak.
type Scheduler struct {
	changes  <-chan struct{}
	scan     func(context.Context) error
	debounce time.Duration
	onError  func(error)
	clock    clock
	running  atomic.Bool
}

// NewScheduler returns a Scheduler that scans with scan, and rescans when
// changes is signalled.
//
// scan is given the context passed to Run, and is expected to return when that
// is done: the scheduler cannot stop a scan that ignores it, and Run does not
// return until the scan has. A scan that is cancelled this way should return
// its context's error, which is not reported. Any other error is reported to
// OnError and the scheduler goes on: one failed scan does not end the watch.
func NewScheduler(changes <-chan struct{}, scan func(context.Context) error, opts SchedulerOptions) *Scheduler {
	s := &Scheduler{
		changes:  changes,
		scan:     scan,
		debounce: opts.Debounce,
		onError:  opts.OnError,
		clock:    opts.clock,
	}
	if s.debounce <= 0 {
		s.debounce = DefaultDebounce
	}
	if s.clock == nil {
		s.clock = realClock{}
	}
	return s
}

// Run scans at once, then after each change as described on Scheduler, until
// ctx is done. It returns ctx's error then, and ErrChangesClosed if the changes
// channel is closed while ctx is still live; a change that was still waiting is
// not scanned. A
// scan that is running when ctx ends is waited for.
func (s *Scheduler) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return ErrSchedulerRunning
	}
	defer s.running.Store(false)

	if err := ctx.Err(); err != nil {
		return err
	}
	s.runScan(ctx)

	var (
		debouncing timer
		expired    <-chan time.Time // nil, which never fires, unless a debounce is running
	)
	defer func() {
		if debouncing != nil {
			debouncing.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, open := <-s.changes:
			if !open {
				// A watcher that was stopped with the context closes its channel
				// as well, and the context is the reason for that, so it is the
				// error to return; select cannot be left to choose between them.
				if err := ctx.Err(); err != nil {
					return err
				}
				return ErrChangesClosed
			}
			if debouncing == nil {
				debouncing = s.clock.NewTimer(s.debounce)
			} else {
				debouncing.Reset(s.debounce)
			}
			expired = debouncing.C()
		case <-expired:
			expired = nil
			// Both can be ready, and a scan must not start after the end.
			if err := ctx.Err(); err != nil {
				return err
			}
			s.runScan(ctx)
		}
	}
}

func (s *Scheduler) runScan(ctx context.Context) {
	err := s.scan(ctx)
	if err != nil && ctx.Err() == nil && s.onError != nil {
		s.onError(err)
	}
}
