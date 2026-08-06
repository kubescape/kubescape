package getter

import (
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
)

func TestKSCloudAPIConnector_Race(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Concurrent writer
	go func() {
		defer wg.Done()
		for i := 0; i < 100000; i++ {
			SetKSCloudAPIConnector(v1.NewEmptyKSCloudAPI())
		}
	}()

	// Concurrent reader
	go func() {
		defer wg.Done()
		for i := 0; i < 100000; i++ {
			_ = GetKSCloudAPIConnector()
		}
	}()

	wg.Wait()
}
