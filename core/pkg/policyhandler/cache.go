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
	expiration int64
	mutex      sync.RWMutex
}

func NewTimedCache[T any](ttl time.Duration) *TimedCache[T] {
	cache := &TimedCache[T]{
		ttl:   ttl,
		isSet: false,
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

	// cache is disabled
	if c.ttl == 0 {
		return
	}

	c.isSet = true
	c.value = value
	c.expiration = time.Now().Add(c.ttl).UnixNano()
}

func (c *TimedCache[T]) Get() (T, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.isSet || time.Now().UnixNano() > c.expiration {
		return c.value, false
	}
	return c.value, true
}

func (c *TimedCache[T]) invalidateTask() {
	for {
		<-time.After(c.ttl)
		if time.Now().UnixNano() > c.expiration {
			c.Invalidate()
		}
	}
}

func (c *TimedCache[T]) Invalidate() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.isSet = false
}
