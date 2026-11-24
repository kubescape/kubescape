package cautils

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/stretchr/testify/assert"
)

// stalledHandler never answers, like the backend client on a black-holed network.
type stalledHandler struct{ started, release chan struct{} }

func newStalledHandler(t *testing.T) stalledHandler {
	h := stalledHandler{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		close(h.release)
		// The worker holds the in-flight guard until it returns; let it go before the next test.
		assert.Eventually(t, func() bool { return !versionCheckRunning.Load() }, 2*time.Second, time.Millisecond)
	})
	return h
}

func (h stalledHandler) CheckLatestVersion(_ context.Context, _ *versioncheck.VersionCheckRequest) error {
	close(h.started)
	<-h.release
	return nil
}

func (h stalledHandler) assertStarted(t *testing.T) {
	select {
	case <-h.started:
	case <-time.After(time.Second):
		t.Fatal("the check never started")
	}
}

type doneHandler struct{ called *bool }

func (h doneHandler) CheckLatestVersion(_ context.Context, _ *versioncheck.VersionCheckRequest) error {
	*h.called = true
	return nil
}

func noRequest() *versioncheck.VersionCheckRequest { return &versioncheck.VersionCheckRequest{} }

func TestCheckLatestVersion_StopsWaitingAtTimeout(t *testing.T) {
	h := newStalledHandler(t)

	start := time.Now()
	CheckLatestVersion(context.Background(), 50*time.Millisecond, h, noRequest)
	assert.Less(t, time.Since(start), 2*time.Second)
	h.assertStarted(t)
}

func TestCheckLatestVersion_StopsWaitingOnCancel(t *testing.T) {
	h := newStalledHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	CheckLatestVersion(ctx, time.Hour, h, noRequest)
	assert.Less(t, time.Since(start), 2*time.Second)
	h.assertStarted(t)
}

func TestCheckLatestVersion_SkipsWhileAnotherCheckRuns(t *testing.T) {
	// The first check gives up waiting but keeps running in the background.
	CheckLatestVersion(context.Background(), 10*time.Millisecond, newStalledHandler(t), noRequest)

	called := false
	CheckLatestVersion(context.Background(), time.Hour, doneHandler{called: &called}, noRequest)
	assert.False(t, called)
}

func TestCheckLatestVersion_SkipsWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	CheckLatestVersion(ctx, time.Hour, doneHandler{called: &called}, noRequest)
	assert.False(t, called)
}

func TestCheckLatestVersion_WaitsForAFastCheck(t *testing.T) {
	called := false
	CheckLatestVersion(context.Background(), time.Hour, doneHandler{called: &called}, noRequest)
	assert.True(t, called)
}
