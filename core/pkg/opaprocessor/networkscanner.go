package opaprocessor

import (
	servicediscovery "github.com/kubescape/kubescape-network-scanner/cmd"
)

// Check if the service is unauthenticated using kubescape-network-scanner.
func isUnauthenticatedService(host string, port int) bool {
	discoveryResults, err := servicediscovery.ScanTargets(host, port)
	if err != nil {
		return false
	}

	if !discoveryResults.IsAuthenticated {
		return true
	}

	return false
}
