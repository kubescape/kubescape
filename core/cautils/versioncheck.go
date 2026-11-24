package cautils

import (
	"context"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
)

// VersionCheckTimeout bounds how long a caller waits for the best-effort update check.
const VersionCheckTimeout = 5 * time.Second

// CheckLatestVersion runs the update check, including building the request
// (which reads the cluster), but returns once timeout passes or ctx is done.
// The backend client ignores ctx, so on a stalled network the check keeps
// running in the background until its request ends: at process exit for the
// CLI, possibly never in a long-running ksserver.
func CheckLatestVersion(ctx context.Context, timeout time.Duration, v versioncheck.IVersionCheckHandler, newRequest func() *versioncheck.VersionCheckRequest) {
	if ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = v.CheckLatestVersion(ctx, newRequest())
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
