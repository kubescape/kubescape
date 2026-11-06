package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// fakeClientWithEventsAccess returns a fake clientset whose access reviews
// answer allowed, or fail with reviewErr when it is set. It records the
// attributes of the last review.
func fakeClientWithEventsAccess(allowed bool, reviewErr error, seen *authorizationv1.ResourceAttributes) *fake.Clientset {
	client := fake.NewClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, k8sruntime.Object, error) {
		if reviewErr != nil {
			return true, nil, reviewErr
		}
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		if seen != nil && review.Spec.ResourceAttributes != nil {
			*seen = *review.Spec.ResourceAttributes
		}
		review.Status.Allowed = allowed
		return true, review, nil
	})
	return client
}

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

	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(context.Background(), fakeClientWithEventsAccess(true, nil, nil))
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
	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(context.Background(), nil)
	require.Nil(t, recorder)
	require.Nil(t, shutdown)
}

// TestSecurityExceptionEventRecorderReviewsClusterWideEventCreate verifies the
// recorder is built when events may be created in every namespace, and that it
// asks for exactly that.
func TestSecurityExceptionEventRecorderReviewsClusterWideEventCreate(t *testing.T) {
	var seen authorizationv1.ResourceAttributes
	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(context.Background(), fakeClientWithEventsAccess(true, nil, &seen))
	require.NotNil(t, recorder)
	require.NotNil(t, shutdown)
	shutdown()

	require.Equal(t, authorizationv1.ResourceAttributes{Verb: "create", Version: "v1", Resource: "events"}, seen)
}

// TestSecurityExceptionEventRecorderDisabledWithoutEventAccess verifies that no
// recorder is returned when the identity may not create events, or when the
// access review itself fails.
func TestSecurityExceptionEventRecorderDisabledWithoutEventAccess(t *testing.T) {
	tests := []struct {
		name      string
		allowed   bool
		reviewErr error
	}{
		{name: "denied", allowed: false},
		{name: "review error", reviewErr: errors.New("connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder, shutdown := newSecurityExceptionEventRecorderWithClient(context.Background(), fakeClientWithEventsAccess(tt.allowed, tt.reviewErr, nil))
			require.Nil(t, recorder)
			require.Nil(t, shutdown)
		})
	}
}

// TestSecurityExceptionEventRecorderDisabledWhenAccessReviewHangs verifies that
// an API server that never answers the access review cannot hold up the scan:
// the review is abandoned after eventsAccessReviewTimeout and no recorder is
// returned.
func TestSecurityExceptionEventRecorderDisabledWhenAccessReviewHangs(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)

	previous := eventsAccessReviewTimeout
	eventsAccessReviewTimeout = 50 * time.Millisecond
	defer func() { eventsAccessReviewTimeout = previous }()

	start := time.Now()
	recorder, shutdown := newSecurityExceptionEventRecorderWithClient(context.Background(), client)
	require.Nil(t, recorder)
	require.Nil(t, shutdown)
	require.Less(t, time.Since(start), 5*time.Second, "the access review must be bounded by eventsAccessReviewTimeout")
}
