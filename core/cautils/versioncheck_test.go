package cautils

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/stretchr/testify/assert"
)

// stalledHandler never answers, like the backend client on a black-holed network.
type stalledHandler struct{ release chan struct{} }

func (h stalledHandler) CheckLatestVersion(_ context.Context, _ *versioncheck.VersionCheckRequest) error {
	<-h.release
	return nil
}

type doneHandler struct{ called *bool }

func (h doneHandler) CheckLatestVersion(_ context.Context, _ *versioncheck.VersionCheckRequest) error {
	*h.called = true
	return nil
}

func noRequest() *versioncheck.VersionCheckRequest { return &versioncheck.VersionCheckRequest{} }

func TestCheckLatestVersion_StopsWaitingAtTimeout(t *testing.T) {
	h := stalledHandler{release: make(chan struct{})}
	defer close(h.release)

	start := time.Now()
	CheckLatestVersion(context.Background(), 50*time.Millisecond, h, noRequest)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestCheckLatestVersion_StopsWaitingOnCancel(t *testing.T) {
	h := stalledHandler{release: make(chan struct{})}
	defer close(h.release)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	CheckLatestVersion(ctx, time.Hour, h, noRequest)
	assert.Less(t, time.Since(start), 2*time.Second)
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
