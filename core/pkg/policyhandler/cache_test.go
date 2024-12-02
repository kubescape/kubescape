package policyhandler

import (
	"testing"
	"time"
)

func TestTimedCache(t *testing.T) {
	tests := []struct {
		name string
		// value ttl
		ttl time.Duration
		// value to set
		value int
		// time to wait before checking if value exists
		wait time.Duration
		// number of times to check if value exists (with wait in between)
		checks int
		// should the value exist in cache
		exists bool
		// expected cache value
		wantVal int
	}{
		{
			name:    "value exists before ttl",
			ttl:     time.Second * 5,
			value:   42,
			wait:    time.Second * 1,
			checks:  2,
			exists:  true,
			wantVal: 42,
		},
		{
			name:   "value does not exist after ttl",
			ttl:    time.Second * 3,
			value:  55,
			wait:   time.Second * 4,
			checks: 1,
			exists: false,
		},
		{
			name:   "cache is disabled (ttl = 0) always returns false",
			ttl:    0,
			value:  55,
			wait:   0,
			checks: 1,
			exists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewTimedCache[int](tt.ttl)
			cache.Set(tt.value)

			for i := 0; i < tt.checks; i++ {
				// Wait for the specified duration
				time.Sleep(tt.wait)

				// Get the value from the cache
				value, exists := cache.Get()

				// Check if value exists
				if exists != tt.exists {
					t.Errorf("Expected exists to be %v, got %v", tt.exists, exists)
				}

				// Check value
				if exists && value != tt.wantVal {
					t.Errorf("Expected value to be %d, got %d", tt.wantVal, value)
				}
			}
		})
	}
}

func TestCache_SetAndGet(t *testing.T) {
	cache := NewTimedCache[int](time.Second * 2)

	cache.Set(42)

	value, exists := cache.Get()
	if !exists || value != 42 {
		t.Errorf("Expected value: %v, Got: %v, Exists: %v", 42, value, exists)
	}
}

func TestCache_Expiration(t *testing.T) {
	cache := NewTimedCache[int](time.Millisecond * 500)

	cache.Set(42)

	time.Sleep(time.Millisecond * 1000) // Wait for expiration

	value, exists := cache.Get()
	if exists {
		t.Errorf("Expected cache to be expired, but got value: %v", value)
	}
}

func TestCache_WithZeroTTL(t *testing.T) {
	cache := NewTimedCache[string](0)

	cache.Set("hello")

	value, exists := cache.Get()
	if exists {
		t.Errorf("Expected cache to be disabled, but got value: %v", value)
	}
}

func TestCache_Invalidate(t *testing.T) {
	cache := NewTimedCache[string](time.Second * 2)

	cache.Set("initial value")

	cache.Invalidate()

	value, exists := cache.Get()
	if exists {
		t.Errorf("Expected cache to be invalidated, but got value: %v", value)
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewTimedCache[int](time.Second * 5)

	go func() {
		cache.Set(42)
	}()

	time.Sleep(time.Second * 1)
	value, exists := cache.Get()
	if !exists || value != 42 {
		t.Errorf("Expected value: %v, Got: %v, Exists: %v", 42, value, exists)
	}

}
