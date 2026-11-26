package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
)

// defaultPolicyReadyWait is how long a tool call that needs policies waits for
// the startup policy load before giving up. It stays below the request
// timeouts MCP clients typically apply, so the caller gets a clear error
// rather than a client-side timeout.
const defaultPolicyReadyWait = 30 * time.Second

// errPolicyNotReady is returned to a tool call that needed the policy bundle
// while the startup load was still running.
var errPolicyNotReady = errors.New("policy bundle is still loading, retry shortly")

// policyStoreLoader is the part of getter.DownloadReleasedPolicy that
// loadPolicyGetter needs.
type policyStoreLoader interface {
	getter.IPolicyGetter
	SetRegoObjectsWithFallback() (fallback bool, err error)
}

// loadPolicyGetter initializes the policy store and returns the getter the
// server should use. It loads the released bundle, and when that is
// unavailable falls back to the policies cached in the local store.
func loadPolicyGetter(drp policyStoreLoader) getter.IPolicyGetter {
	var pg getter.IPolicyGetter = drp

	fallback, err := drp.SetRegoObjectsWithFallback()
	switch {
	case err != nil:
		logger.L().Warning("Failed to initialize policy store at startup (falling back to direct download later)", helpers.Error(err))
	case fallback:
		logger.L().Warning("Failed to get policies from github release, loading policies from cache")
		paths := make([]string, 0, len(getter.NativeFrameworks))
		for _, fw := range getter.NativeFrameworks {
			paths = append(paths, getter.GetDefaultPath(fw+".json"))
		}
		pg = cachedPolicy{getter.NewLoadPolicy(paths)}
	}
	return pg
}

// cachedPolicy is the policy cache the server falls back to when the release
// cannot be fetched. Like the CLI fallback it serves the NativeFrameworks
// files, which are also all list_frameworks reports. The getter is shared by
// every tool, so it cannot know the requested frameworks up front: a framework
// that is not native is read by name from its own cache file
// (getter.PolicyCachePath), so workloadscan, clusterscan or any framework
// cached before can still be scanned.
type cachedPolicy struct {
	*getter.LoadPolicy
}

// runScan reads exceptions, control inputs and attack tracks off the policy
// getter by type assertion, so losing one would silently degrade scans.
var (
	_ getter.IExceptionsGetter     = cachedPolicy{}
	_ getter.IControlsInputsGetter = cachedPolicy{}
	_ getter.IAttackTracksGetter   = cachedPolicy{}
)

func (c cachedPolicy) GetFramework(name string) (*reporthandling.Framework, error) {
	framework, err := c.LoadPolicy.GetFramework(name)
	if !errors.Is(err, getter.ErrFrameworkNotMatching) {
		return framework, err
	}
	path, pathErr := getter.PolicyCachePath(name)
	if pathErr != nil {
		return nil, err
	}
	return getter.NewLoadPolicy([]string{path}).GetFramework(name)
}

// startPolicyLoad runs load in the background and publishes its result as the
// server's policyGetter. Until it returns, readyPolicyGetter blocks callers,
// so a tool never sees an empty or half-loaded store. It starts at most one
// load per server.
func (ksServer *KubescapeMcpserver) startPolicyLoad(load func() getter.IPolicyGetter) {
	ksServer.policyGetterMu.Lock()
	if ksServer.policyReady != nil {
		ksServer.policyGetterMu.Unlock()
		return
	}
	ready := make(chan struct{})
	ksServer.policyReady = ready
	ksServer.policyGetterMu.Unlock()

	go func() {
		defer close(ready)
		start := time.Now()
		pg := load()

		ksServer.policyGetterMu.Lock()
		ksServer.policyGetter = pg
		ksServer.policyGetterMu.Unlock()
		logger.L().Info("Policy store ready", helpers.String("elapsed", time.Since(start).Round(time.Millisecond).String()))
	}()
}

// readyPolicyGetter returns the policy getter once the startup load has
// finished. It returns immediately for a server with no load in progress. It
// gives up when ctx is done, or after policyReadyWait with errPolicyNotReady.
func (ksServer *KubescapeMcpserver) readyPolicyGetter(ctx context.Context) (getter.IPolicyGetter, error) {
	ksServer.policyGetterMu.Lock()
	ready := ksServer.policyReady
	wait := ksServer.policyReadyWait
	ksServer.policyGetterMu.Unlock()

	if ready != nil {
		select {
		case <-ready:
		default:
			if wait <= 0 {
				wait = defaultPolicyReadyWait
			}
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ready:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, fmt.Errorf("%w (waited %s)", errPolicyNotReady, wait)
			}
		}
	}
	return ksServer.getPolicyGetter(), nil
}
