package opaprocessor

import (
	"fmt"
	"time"

	logger "github.com/kubescape/go-logger"
	servicediscovery "github.com/kubescape/kubescape-network-scanner/cmd"
)

const (
	Timeout = time.Second * 3
)

// Check if the service is unauthenticated using kubescape-network-scanner.
func isUnauthenticatedService(host string, port int) bool {
	// Run the network scanner in a goroutine and wait for the result.
	results := make(chan bool, 1)
	go func() {
		discoveryResults, err := servicediscovery.ScanTargets(host, port)
		if err != nil {
			results <- false
		} else if !discoveryResults.IsAuthenticated && discoveryResults.ApplicationLayer != "" {
			results <- true
		}

		results <- false
	}()

	select {
	case result := <-results:
		return result
	case <-time.After(Timeout):
		logger.L().Error(fmt.Sprintf("Timeout while scanning service: %s", host))
		return false
	}
}
