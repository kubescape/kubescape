package policyhandler

import (
	"sync"
	"time"
)

// TimedCache provides functionality for managing a timed cache.
// The timed cache holds values for a specified time duration (TTL).
// After the TTL has passed, the values are invalidated.
//
// The cache is thread safe and supports keyed entries.
type TimedCache[T any] struct {
	values     map[string]cacheEntry[T]
	ttl        time.Duration
	mutex      sync.RWMutex
	stopChan   chan struct{} // to stop the invalidateTask goroutine
}

type cacheEntry[T any] struct {
	value      T
	expiration time.Time
}

func NewTimedCache[T any](ttl time.Duration) *TimedCache[T] {
	cache := &TimedCache[T]{
		values:   make(map[string]cacheEntry[T]),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}

	// start the invalidate task only when the ttl is greater than 0 (cache is enabled)
	if ttl > 0 {
		go cache.invalidateTask()
	}

	return cache
}

func (c *TimedCache[T]) Set(value T) {
	c.SetWithKey("", value)
}

func (c *TimedCache[T]) SetWithKey(key string, value T) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.ttl == 0 {
		return
	}

	expiration := time.Now().Add(c.ttl)
	c.values[key] = cacheEntry[T]{
		value:      value,
		expiration: expiration,
	}
}

func (c *TimedCache[T]) Get() (T, bool) {
	return c.GetWithKey("")
}

func (c *TimedCache[T]) GetWithKey(key string) (T, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, found := c.values[key]
	if !found {
		var zero T
		return zero, false
	}

	if time.Now().After(entry.expiration) {
		var zero T
		return zero, false
	}

	return entry.value, true
}

func (c *TimedCache[T]) invalidateTask() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			now := time.Now()
			for k, v := range c.values {
				if now.After(v.expiration) {
					delete(c.values, k)
				}
			}
			c.mutex.Unlock()
		case <-c.stopChan:
			return
		}
	}
}

func (c *TimedCache[T]) Stop() {
	close(c.stopChan)
}

func (c *TimedCache[T]) Invalidate() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.values = make(map[string]cacheEntry[T])
}
