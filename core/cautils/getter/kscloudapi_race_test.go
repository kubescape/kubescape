package getter

import (
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
)

func TestKSCloudAPIConnector_Race(t *testing.T) {
	globalMx.Lock()
	defer globalMx.Unlock()

	// Save and restore global state
	globalKSCloudAPIConnectorMutex.Lock()
	original := globalKSCloudAPIConnector
	globalKSCloudAPIConnectorMutex.Unlock()

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
	startBarrier := make(chan struct{})

	// 8 writers
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier
			for i := 0; i < 100000; i++ {
				SetKSCloudAPIConnector(v1.NewEmptyKSCloudAPI())
			}
		}()
	}

	// 8 readers
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier
			for i := 0; i < 100000; i++ {
				_ = GetKSCloudAPIConnector()
			}
		}()
	}

	close(startBarrier) // unleash all goroutines
	wg.Wait()
}
