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

func TestTimedCacheFreshSetNotClearedByExpiredTick(t *testing.T) {
	cache := NewTimedCache[string](10 * time.Millisecond)

	cache.Set("original")

	time.Sleep(25 * time.Millisecond)

	cache.Set("fresh")

	val, ok := cache.Get()
	if !ok || val != "fresh" {
		t.Errorf("Expected 'fresh' after Set(), got val=%q ok=%v", val, ok)
	}

	time.Sleep(5 * time.Millisecond)

	val, ok = cache.Get()
	if !ok || val != "fresh" {
		t.Errorf("Expected 'fresh' to persist within TTL, got val=%q ok=%v", val, ok)
	}
}

func TestTimedCacheSetSurvivesBackgroundInvalidation(t *testing.T) {
	const ttl = 20 * time.Millisecond
	cache := NewTimedCache[string](ttl)
	defer cache.Stop()

	time.Sleep(3 * ttl)

	i := 0
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		cache.Set("v")
		val, ok := cache.Get()
		if !ok || val != "v" {
			t.Fatalf("iteration %d: Get() returned ok=%v val=%q after Set() within TTL", i, ok, val)
		}
		time.Sleep(ttl / 2)
		i++
	}
}
