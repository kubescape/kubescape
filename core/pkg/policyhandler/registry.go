package policyhandler

import (
	"sync"
	"time"
)

// defaultIdleEvictionWindow bounds how long a shared PolicyHandler survives in
// the registry with nothing actively holding it, even when POLICIES_CACHE_TTL
// is 0 (caching disabled) and there is therefore no cache-driven reason to
// keep reusing it. Without an upper bound here, every distinct cluster name
// ever passed to NewPolicyHandler would leave a permanent entry behind for
// the life of the process -- the exact long-running httphandler scenario
// that motivated the original singleton in the first place (issue #2004).
const defaultIdleEvictionWindow = 5 * time.Minute

// policyHandlerEntry is one registry slot: the shared handler for a cluster,
// how many active acquireHandler callers are using it, and when it was last
// touched by any path (getHandler or acquireHandler).
type policyHandlerEntry struct {
	handler    *PolicyHandler
	refCount   int
	lastAccess time.Time
}

// policyHandlerRegistry is a mutex-guarded, cluster-keyed registry of
// PolicyHandlers. It replaces the previous bare singleton, which caused two
// bugs under concurrent or long-running multi-cluster use: a stale-cache leak
// (a later call for a different cluster silently reused the first cluster's
// caches) and, if fixed naively by never evicting, an unbounded memory leak
// (one entry retained forever per distinct cluster name).
//
// Entries with no active acquireHandler caller (refCount == 0) are reclaimed
// by an idle sweep run on every registry access, so getHandler -- used by
// every existing call site, none of which release explicitly -- stays
// memory-bounded without requiring any caller changes.
type policyHandlerRegistry struct {
	mu      sync.Mutex
	entries map[string]*policyHandlerEntry
}

var globalRegistry = &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}

// idleWindow returns how long an unreferenced entry may sit idle before a
// sweep evicts it. Tied to POLICIES_CACHE_TTL when caching is on, since
// there's no reason to hold a handler open longer than its cache is useful;
// falls back to defaultIdleEvictionWindow when caching is disabled.
func (r *policyHandlerRegistry) idleWindow() time.Duration {
	if ttl := getPoliciesCacheTtl(); ttl > 0 {
		return ttl
	}
	return defaultIdleEvictionWindow
}

// sweepLocked evicts and closes every unreferenced entry idle past window.
// Must be called with r.mu held. Close runs in the background so a slow
// TimedCache shutdown never blocks a caller that's just trying to get a
// handler for an unrelated cluster.
func (r *policyHandlerRegistry) sweepLocked(now time.Time, window time.Duration) {
	for name, entry := range r.entries {
		if entry.refCount <= 0 && now.Sub(entry.lastAccess) > window {
			delete(r.entries, name)
			go entry.handler.Close()
		}
	}
}

// getHandler returns the shared, cluster-isolated PolicyHandler for
// clusterName, creating it if needed. There is no release call here by
// design -- this is what NewPolicyHandler exposes, and none of its existing
// callers are structured to release a handler when they're done. The idle
// sweep reclaims it instead.
func (r *policyHandlerRegistry) getHandler(clusterName string) *PolicyHandler {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sweepLocked(now, r.idleWindow())

	entry, ok := r.entries[clusterName]
	if !ok {
		entry = &policyHandlerEntry{handler: NewRequestScopedPolicyHandler(clusterName)}
		r.entries[clusterName] = entry
	}
	entry.lastAccess = now
	return entry.handler
}

// acquireHandler returns the shared PolicyHandler for clusterName and a
// release function that must be deferred. Meant for orchestration paths --
// e.g. the fleet work in issue #1990 -- that scan the same cluster
// sequentially in one goroutine and want the caching benefit guaranteed for
// the duration of that use, rather than left to the idle sweep.
func (r *policyHandlerRegistry) acquireHandler(clusterName string) (*PolicyHandler, func()) {
	now := time.Now()
	r.mu.Lock()
	r.sweepLocked(now, r.idleWindow())

	entry, ok := r.entries[clusterName]
	if !ok {
		entry = &policyHandlerEntry{handler: NewRequestScopedPolicyHandler(clusterName)}
		r.entries[clusterName] = entry
	}
	entry.refCount++
	entry.lastAccess = now
	r.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			entry.refCount--
			entry.lastAccess = time.Now()
			r.mu.Unlock()
		})
	}
	return entry.handler, release
}

// size reports the current number of live registry entries. Test helper.
func (r *policyHandlerRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// closeAll evicts and closes every entry regardless of refCount. Test helper
// for tearing down a registry built in a test.
func (r *policyHandlerRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, entry := range r.entries {
		delete(r.entries, name)
		entry.handler.Close()
	}
}
