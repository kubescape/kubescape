package policyhandler

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTimedCacheInvalidateTwiceNoPanic(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)
	cache.Set("test-value")

	cache.Invalidate()
	cache.Invalidate()
}

func TestTimedCacheInvalidateAfterStopNoPanic(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)
	cache.Set("test-value")

	cache.Stop()
	cache.Invalidate()
}

func TestTimedCacheRaceInvalidateAndStopNoPanic(t *testing.T) {
	var panicCount atomic.Int64

	for i := 0; i < 100; i++ {
		cache := NewTimedCache[string](1 * time.Hour)
		cache.Set("test")

		var innerWg sync.WaitGroup
		innerWg.Add(2)

		var panicErr error
		var panicMu sync.Mutex

		go func() {
			defer innerWg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicMu.Lock()
					panicErr = fmt.Errorf("%v", r)
					panicMu.Unlock()
				}
			}()
			cache.Invalidate()
		}()

		go func() {
			defer innerWg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicMu.Lock()
					panicErr = fmt.Errorf("%v", r)
					panicMu.Unlock()
				}
			}()
			cache.Stop()
		}()

		innerWg.Wait()

		if panicErr != nil {
			panicCount.Add(1)
		}
	}

	if panicCount.Load() > 0 {
		t.Errorf("%d panics occurred during race", panicCount.Load())
	}
}

func TestTimedCacheStopIdempotent(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)
	cache.Set("test-value")

	cache.Stop()
	cache.Stop()
}

func TestTimedCacheStopWaitsForGoroutine(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)
	cache.Set("test-value")

	goroutineExited := make(chan bool, 1)

	go func() {
		cache.Stop()
		goroutineExited <- true
	}()

	select {
	case <-goroutineExited:
	case <-time.After(500 * time.Millisecond):
		t.Error("Stop() did not return after 500ms; goroutine may not have exited")
	}
}

func TestTimedCacheSetCallsInvalidateOnExpiry(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)

	cache.Set("test-value")
	val, ok := cache.Get()
	if !ok || val != "test-value" {
		t.Errorf("Expected to get 'test-value', got '%s', ok=%v", val, ok)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, ok = cache.Get()
		if !ok {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}

	t.Error("Cache did not expire after 500ms")
}

func TestTimedCacheBasicSetGet(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)

	_, ok := cache.Get()
	if ok {
		t.Error("Expected cache to be empty initially")
	}

	cache.Set("test-value")
	val, ok := cache.Get()
	if !ok || val != "test-value" {
		t.Errorf("Expected 'test-value', got '%s', ok=%v", val, ok)
	}
}

func TestTimedCacheZeroTTLNoGoroutine(t *testing.T) {
	cache := NewTimedCache[string](0)

	cache.Set("test-value")

	_, ok := cache.Get()
	if ok {
		t.Error("Expected cache to be disabled with TTL=0")
	}

	cache.Stop()
	cache.Invalidate()
}

func TestTimedCacheMultipleInvalidateBeforeExpiry(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)

	cache.Set("value1")
	cache.Invalidate()
	cache.Invalidate()
	cache.Invalidate()

	val, ok := cache.Get()
	if ok {
		t.Error("Expected cache to be invalid after Invalidate()")
	}
	_ = val
}

func TestTimedCacheCacheReusableAfterInvalidate(t *testing.T) {
	cache := NewTimedCache[string](1 * time.Hour)

	cache.Set("value1")
	val, ok := cache.Get()
	if !ok || val != "value1" {
		t.Errorf("Expected 'value1', got '%s', ok=%v", val, ok)
	}

	cache.Invalidate()

	_, ok = cache.Get()
	if ok {
		t.Error("Expected cache to be empty after Invalidate()")
	}

	cache.Set("value2")
	val, ok = cache.Get()
	if !ok || val != "value2" {
		t.Errorf("Expected 'value2' after re-Set, got '%s', ok=%v", val, ok)
	}
}

func TestTimedCacheGetReturnsStaleValue(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)
	cache.Set("original")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, ok := cache.Get()
		if !ok {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}

	t.Error("Cache did not expire after 500ms")
}

func TestTimedCacheExpirationWorksAfterInvalidate(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)

	cache.Set("value1")
	_, ok := cache.Get()
	if !ok {
		t.Fatal("Expected value1 to be set")
	}

	cache.Invalidate()
	_, ok = cache.Get()
	if ok {
		t.Fatal("Expected cache to be empty after Invalidate()")
	}

	cache.Set("value2")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, ok = cache.Get()
		if !ok {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}

	t.Error("TTL expiration did not fire after Invalidate()")
}

func TestTimedCacheMultipleInvalidatesDontBreakTTL(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)

	cache.Set("v1")
	cache.Invalidate()
	cache.Invalidate()
	cache.Set("v2")
	cache.Invalidate()
	cache.Set("v3")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, ok := cache.Get()
		if !ok {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}

	t.Error("TTL expiration did not fire after multiple Invalidate() calls")
}

// TestTimedCacheTOCTOURace is a deterministic regression test for the TOCTOU bug
// that existed in invalidateTask before the fix.
//
// Old buggy flow inside invalidateTask:
//
//	lock → check expiry (true) → unlock
//	                              ← Set("fresh") runs here (lock is free)
//	invalidateExternal() → clears "fresh"  ← BUG
//
// Fixed flow: the write lock is held across the check AND invalidateLocked(), so
// any concurrent Set() blocks until after invalidation and the fresh value is safe.
//
// Synchronization strategy:
//   - invalidateHook fires before invalidateLocked (inside the write lock in fixed code,
//     outside it in the old buggy code). It signals a goroutine to call Set("fresh")
//     and waits, ensuring Set runs in the TOCTOU window if the lock is free.
//   - afterInvalidateHook fires after invalidateLocked (inside the write lock in fixed
//     code, after invalidateExternal() in old code). It signals that the full invalidation
//     cycle is complete, giving the test a reliable point to assert from.
//
// On old buggy code: Set("fresh") succeeds inside the gap, hook returns, then
// invalidateExternal clears "fresh". afterInvalidateHook fires after the clear.
// Test asserts after both signals → Get() returns false → FAIL (correctly).
//
// On fixed code: Set("fresh") blocks on the held write lock. Hook times out, then
// invalidateLocked runs (clearing the old expiration). afterInvalidateHook fires.
// Lock is released. Set("fresh") then runs. Test asserts after both signals →
// Get() returns "fresh" → PASS.
func TestTimedCacheTOCTOURace(t *testing.T) {
	const ttl = 20 * time.Millisecond

	var armed atomic.Bool
	var afterArmed atomic.Bool
	hookReached := make(chan struct{})
	setDone := make(chan struct{})
	afterInvalidateDone := make(chan struct{})

	cache := NewTimedCache[string](ttl)
	defer cache.Stop()

	cache.invalidateHook = func() {
		if !armed.CompareAndSwap(true, false) {
			return
		}
		afterArmed.Store(true)
		close(hookReached)
		select {
		case <-setDone:
			// old buggy path: Set("fresh") completed inside the lock-release gap;
			// invalidation will run next and clear it
		case <-time.After(50 * time.Millisecond):
			// fixed path: Set("fresh") is blocked on the write lock held here;
			// it runs only after invalidateLocked and the lock are released
		}
	}

	cache.afterInvalidateHook = func() {
		if !afterArmed.CompareAndSwap(true, false) {
			return
		}
		close(afterInvalidateDone)
	}

	cache.Set("seed")
	time.Sleep(2 * ttl) // let "seed" expire and early ticks fire with hooks unarmed
	armed.Store(true)   // arm for the next qualifying tick

	go func() {
		select {
		case <-hookReached:
		case <-time.After(200 * time.Millisecond):
			t.Error("invalidateHook never reached the invalidation point")
			return
		}
		cache.Set("fresh")
		close(setDone)
	}()

	// Wait for the full invalidation cycle to complete before asserting.
	select {
	case <-afterInvalidateDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("afterInvalidateHook never fired; invalidation did not complete")
	}

	// In fixed code, Set("fresh") may still be running (it was blocked on the lock
	// during the hook; the lock is released after afterInvalidateHook fires). Wait
	// for it to finish before reading the cache.
	select {
	case <-setDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Set(\"fresh\") goroutine did not complete")
	}

	val, ok := cache.Get()
	if !ok || val != "fresh" {
		t.Errorf("TOCTOU bug: 'fresh' was cleared by the expired-tick invalidation; got val=%q ok=%v", val, ok)
	}
}
