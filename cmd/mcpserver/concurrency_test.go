package mcpserver

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type doneObservedContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *doneObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func receiveWithin[T any](t *testing.T, ch <-chan T, event string) T {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", event)
		var zero T
		return zero
	}
}

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

func TestDoScanChan_NewCallerDoesNotInheritCanceledGeneration(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	oldStarted := make(chan struct{})
	oldCanceled := make(chan struct{})
	releaseOld := make(chan struct{})
	oldReturned := make(chan struct{})
	firstDone := make(chan error, 1)
	var releaseOldOnce sync.Once
	releaseOldScan := func() {
		releaseOldOnce.Do(func() { close(releaseOld) })
	}
	t.Cleanup(cancelFirst)
	t.Cleanup(releaseOldScan)

	go func() {
		_, err := ksServer.doScanChan(firstCtx, "reused_key", func(scanCtx context.Context) (interface{}, error) {
			close(oldStarted)
			<-scanCtx.Done()
			close(oldCanceled)
			<-releaseOld
			close(oldReturned)
			return nil, scanCtx.Err()
		})
		firstDone <- err
	}()

	receiveWithin(t, oldStarted, "old scan to start")
	cancelFirst()
	assert.ErrorIs(t, receiveWithin(t, firstDone, "first caller to return"), context.Canceled)
	receiveWithin(t, oldCanceled, "old scan to observe cancellation")

	enteredSelect := make(chan struct{})
	freshCtx := &doneObservedContext{
		Context:  context.Background(),
		observed: enteredSelect,
	}
	freshStarted := make(chan struct{})
	freshDone := make(chan error, 1)
	var freshResult interface{}
	go func() {
		var err error
		freshResult, err = ksServer.doScanChan(freshCtx, "reused_key", func(context.Context) (interface{}, error) {
			close(freshStarted)
			return "fresh result", nil
		})
		freshDone <- err
	}()

	// Done is evaluated only after DoChan has either joined the old call or
	// registered a new generation. Keep the old call alive until that point so
	// this test exercises the singleflight cleanup window deterministically.
	receiveWithin(t, enteredSelect, "fresh caller to register with singleflight")
	releaseOldScan()

	assert.NoError(t, receiveWithin(t, freshDone, "fresh caller to return"))
	assert.Equal(t, "fresh result", freshResult)
	select {
	case <-freshStarted:
	default:
		t.Error("fresh scan function was not called")
	}
	receiveWithin(t, oldReturned, "old scan function to return")
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
