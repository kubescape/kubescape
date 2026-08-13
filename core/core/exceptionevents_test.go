package core

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// pollGoroutineCount waits until cond returns true, giving the scheduler and
// background goroutines time to settle. A plain poll loop is used instead of
// require.Eventually because the latter's internal timer goroutines perturb the
// goroutine count this test asserts on.
func pollGoroutineCount(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestSecurityExceptionEventRecorderShutdownStopsWatcher verifies that the
// event broadcaster created by newSecurityExceptionEventRecorderWithClient is
// shut down when the caller invokes the returned shutdown closure. Before the
// shutdown closure existed, the broadcaster's StartEventWatcher goroutine was
// leaked on every scan against a live cluster, growing unbounded in
// long-running modes like httphandler.
func TestSecurityExceptionEventRecorderShutdownStopsWatcher(t *testing.T) {
	baseline := runtime.NumGoroutine()

	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(fake.NewClientset())
	require.NotNil(t, recorder, "a recorder must be returned for a valid client")
	require.NotNil(t, shutdown, "a shutdown closure must be returned for a valid client")

	recorder.Eventf(&corev1.ObjectReference{}, corev1.EventTypeWarning, "TestReason", "a test event")

	// The broadcaster runs a distribution loop and a StartEventWatcher
	// goroutine, so the count must rise above the baseline.
	require.True(t, pollGoroutineCount(2*time.Second, func() bool {
		return runtime.NumGoroutine() > baseline
	}), "the event watcher goroutine must be running")

	shutdown()

	// Both goroutines must terminate after Shutdown, restoring the baseline.
	require.True(t, pollGoroutineCount(2*time.Second, func() bool {
		return runtime.NumGoroutine() <= baseline
	}), "the event watcher goroutine must stop after shutdown")
}

func TestSecurityExceptionEventRecorderWithNilClient(t *testing.T) {
	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(nil)
	require.Nil(t, recorder)
	require.Nil(t, shutdown)
}
