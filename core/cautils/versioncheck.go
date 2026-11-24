package cautils

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
)

// VersionCheckTimeout bounds how long a caller waits for the best-effort update check.
const VersionCheckTimeout = 5 * time.Second

// versionCheckRunning is held by the worker until its check returns, not
// until its caller stops waiting.
var versionCheckRunning atomic.Bool

// CheckLatestVersion runs the update check, including building the request
// (which reads the cluster), but returns once timeout passes or ctx is done.
// The backend client ignores ctx, so on a stalled network the check keeps
// running in the background until its request ends. Only one check runs at a
// time: the backend writes package globals without locking, so a call made
// while an earlier check is still running skips the check.
func CheckLatestVersion(ctx context.Context, timeout time.Duration, v versioncheck.IVersionCheckHandler, newRequest func() *versioncheck.VersionCheckRequest) {
	if ctx.Err() != nil {
		return
	}
	if !versionCheckRunning.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer versionCheckRunning.Store(false) // runs before close(done), so a caller that saw done can check again
		_ = v.CheckLatestVersion(ctx, newRequest())
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
