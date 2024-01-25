package opaprocessor

import (
	"strconv"

	servicediscovery "github.com/kubescape/kubescape-network-scanner/cmd"
)

// Check if the service is unauthenticated using kubescape-network-scanner.
func isUnauthenticatedService(host, port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}

	discoveryResults, err := servicediscovery.ScanTargets(host, portInt)
	if err != nil {
		return false
	}

	if !discoveryResults.IsAuthenticated {
		return true
	}

	return false
}
