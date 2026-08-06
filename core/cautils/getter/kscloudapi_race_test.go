package getter

import (
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
)

func TestKSCloudAPIConnector_Race(t *testing.T) {
	// Save and restore global state
	globalKSCloudAPIConnectorMutex.RLock()
	original := globalKSCloudAPIConnector
	globalKSCloudAPIConnectorMutex.RUnlock()

	t.Cleanup(func() {
		globalKSCloudAPIConnectorMutex.Lock()
		globalKSCloudAPIConnector = original
		globalKSCloudAPIConnectorMutex.Unlock()
	})

	// Reset to nil to test lazy initialization path
	globalKSCloudAPIConnectorMutex.Lock()
	globalKSCloudAPIConnector = nil
	globalKSCloudAPIConnectorMutex.Unlock()

	var wg sync.WaitGroup
	var startBarrier sync.WaitGroup

	wg.Add(2)
	startBarrier.Add(1)

	// Concurrent writer
	go func() {
		defer wg.Done()
		startBarrier.Wait()
		for i := 0; i < 100000; i++ {
			SetKSCloudAPIConnector(v1.NewEmptyKSCloudAPI())
		}
	}()

	// Concurrent reader
	go func() {
		defer wg.Done()
		startBarrier.Wait()
		for i := 0; i < 100000; i++ {
			_ = GetKSCloudAPIConnector()
		}
	}()

	// Release the barrier to start both goroutines simultaneously
	startBarrier.Done()

	wg.Wait()
}
