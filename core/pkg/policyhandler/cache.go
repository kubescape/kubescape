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
	stopped    uint32
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

	if atomic.LoadUint32(&c.stopped) != cacheStateActive {
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
				c.invalidateLocked()
			}
			c.mutex.Unlock()
		case <-c.stopChan:
			return
		}
	}
}

func (c *TimedCache[T]) Stop() {
	if !atomic.CompareAndSwapUint32(&c.stopped, cacheStateActive, cacheStateStopping) {
		return
	}
	close(c.stopChan)
	c.stopWg.Wait()
}

func (c *TimedCache[T]) Invalidate() {
	if atomic.LoadUint32(&c.stopped) != cacheStateActive {
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
	if atomic.LoadUint32(&c.stopped) != cacheStateActive {
		return
	}
	c.isSet = false
}
