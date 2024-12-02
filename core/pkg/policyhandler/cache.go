package policyhandler

import (
	"sync"
	"time"
)

// TimedCache provides functionality for managing a timed cache.
// The timed cache holds a value for a specified time duration (TTL).
// After the TTL has passed, the value is invalidated.
//
// The cache is thread safe.
type TimedCache[T any] struct {
	value      T
	isSet      bool
	ttl        time.Duration
	expiration time.Time
	mutex      sync.RWMutex
	stopChan   chan struct{} // to stop the invalidateTask goroutine
}

func NewTimedCache[T any](ttl time.Duration) *TimedCache[T] {
	cache := &TimedCache[T]{
		ttl:      ttl,
		isSet:    false,
		stopChan: make(chan struct{}),
	}

	// start the invalidate task only when the ttl is greater than 0 (cache is enabled)
	if ttl > 0 {
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

	// Signal invalidation to Get() if cache is already expired
	if time.Now().After(c.expiration) {
		c.Invalidate()
	}
}

func (c *TimedCache[T]) Get() (T, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// If the invalidateTask() goroutine is currently invalidating the cache,
	// the Get() method may return the stale cached value before the invalidation is complete.
	// To avoid the stale cached value, we're requiring the Get() method to wait for the invalidation signal before returning the value.
	select {
	case <-c.stopChan:
		return c.value, false
	default:
		if !c.isSet || time.Now().After(c.expiration) {
			return c.value, false
		}
		return c.value, true
	}
}

func (c *TimedCache[T]) invalidateTask() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			expired := time.Now().After(c.expiration)
			c.mutex.Unlock()
			if expired {
				c.Invalidate()
			}
		case <-c.stopChan:
			return
		default:
			// Check if TTL is still non-zero and return if true, to avoid possible memory leaks
			if c.ttl == 0 {
				return
			}
		}
	}
}

func (c *TimedCache[T]) Stop() {
	close(c.stopChan)
}

func (c *TimedCache[T]) Invalidate() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.isSet = false
	close(c.stopChan)
	c.stopChan = make(chan struct{})
}
