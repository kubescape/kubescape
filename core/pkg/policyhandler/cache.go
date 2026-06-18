package policyhandler

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	cacheStateActive uint32 = iota
	cacheStateStopping
)

type TimedCache[T any] struct {
	value      T
	isSet      bool
	ttl        time.Duration
	expiration time.Time
	mutex      sync.RWMutex
	stopChan   chan struct{}
	stopWg     sync.WaitGroup
	stopped    atomic.Uint32
	// invalidateHook, if non-nil, is called inside invalidateTask after the expiry
	// check succeeds and before invalidateLocked. In the fixed implementation this
	// call occurs while the write lock is held, so a concurrent Set blocks until
	// after invalidation. Tests set this field to observe that property; it is
	// always nil outside of tests.
	invalidateHook func()
	// afterInvalidateHook, if non-nil, is called inside invalidateTask immediately
	// after invalidateLocked returns, still while the write lock is held. Tests use
	// this to know when the full invalidation cycle is complete. Always nil outside
	// of tests.
	afterInvalidateHook func()
}

func NewTimedCache[T any](ttl time.Duration) *TimedCache[T] {
	cache := &TimedCache[T]{
		ttl:      ttl,
		isSet:    false,
		stopChan: make(chan struct{}),
	}

	if ttl > 0 {
		cache.stopWg.Add(1)
		go cache.invalidateTask()
	}

	return cache
}

func (c *TimedCache[T]) Set(value T) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.ttl == 0 {
		return
	}

	c.isSet = true
	c.value = value
	c.expiration = time.Now().Add(c.ttl)

	if time.Now().After(c.expiration) {
		c.invalidateLocked()
	}
}

func (c *TimedCache[T]) Get() (T, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.stopped.Load() != cacheStateActive {
		return c.value, false
	}

	if !c.isSet || time.Now().After(c.expiration) {
		return c.value, false
	}
	return c.value, true
}

func (c *TimedCache[T]) invalidateTask() {
	defer c.stopWg.Done()

	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			if time.Now().After(c.expiration) {
				if c.invalidateHook != nil {
					c.invalidateHook()
				}
				c.invalidateLocked()
				if c.afterInvalidateHook != nil {
					c.afterInvalidateHook()
				}
			}
			c.mutex.Unlock()
		case <-c.stopChan:
			return
		}
	}
}

func (c *TimedCache[T]) Stop() {
	if !c.stopped.CompareAndSwap(cacheStateActive, cacheStateStopping) {
		return
	}
	close(c.stopChan)
	c.stopWg.Wait()
}

func (c *TimedCache[T]) Invalidate() {
	if c.stopped.Load() != cacheStateActive {
		return
	}
	c.invalidateExternal()
}

func (c *TimedCache[T]) invalidateExternal() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.invalidateLocked()
}

func (c *TimedCache[T]) invalidateLocked() {
	if c.stopped.Load() != cacheStateActive {
		return
	}
	c.isSet = false
}
