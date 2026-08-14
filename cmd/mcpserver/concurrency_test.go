package mcpserver

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDoScanChan_Deduplication(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	var runCount int
	var mu sync.Mutex

	scanFunc := func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		runCount++
		mu.Unlock()
		time.Sleep(100 * time.Millisecond) // Simulate work
		return "result", nil
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Fire two requests with the same key
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			res, err := ksServer.doScanChan(context.Background(), "same_key", scanFunc)
			assert.NoError(t, err)
			assert.Equal(t, "result", res)
		}()
	}

	wg.Wait()

	// It should have only run once
	mu.Lock()
	assert.Equal(t, 1, runCount)
	mu.Unlock()

	// Fire another request with a different key
	res, err := ksServer.doScanChan(context.Background(), "different_key", scanFunc)
	assert.NoError(t, err)
	assert.Equal(t, "result", res)

	mu.Lock()
	assert.Equal(t, 2, runCount)
	mu.Unlock()
}

func TestDoScanChan_Cancellation(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	ctx, cancel := context.WithCancel(context.Background())
	scanStarted := make(chan struct{})
	scanFinished := make(chan struct{})

	scanFunc := func(scanCtx context.Context) (interface{}, error) {
		close(scanStarted)
		time.Sleep(200 * time.Millisecond)
		close(scanFinished)
		return "result", nil
	}

	go func() {
		// Wait for scan to start, then cancel the caller's context
		<-scanStarted
		cancel()
	}()

	res, err := ksServer.doScanChan(ctx, "cancel_key", scanFunc)

	// The caller should get the cancellation error immediately
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, res)

	// The background scan should still be running and finish cleanly
	<-scanFinished
}

func TestDoScanChan_ConcurrencyLimit(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	var activeScans int
	var maxActiveScans int
	var mu sync.Mutex

	scanStarted := make(chan struct{})
	blockScan := make(chan struct{})

	scanFunc := func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		activeScans++
		if activeScans > maxActiveScans {
			maxActiveScans = activeScans
		}
		mu.Unlock()

		scanStarted <- struct{}{}
		<-blockScan // Wait until allowed to finish

		mu.Lock()
		activeScans--
		mu.Unlock()
		return "result", nil
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Start 3 different scans
	for i := 0; i < 3; i++ {
		go func(id int) {
			defer wg.Done()
			ksServer.doScanChan(context.Background(), fmt.Sprintf("scan_%d", id), scanFunc)
		}(i)
	}

	// Wait for the first two to start
	<-scanStarted
	<-scanStarted

	// At this point, the third scan should be blocked by the semaphore
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	assert.Equal(t, 2, activeScans) // Only 2 should be active
	mu.Unlock()

	// Release the blocked scans
	close(blockScan)

	// The third scan should now run and finish
	<-scanStarted
	wg.Wait()

	mu.Lock()
	assert.Equal(t, 2, maxActiveScans) // Never exceeded 2 concurrent
	mu.Unlock()
}
