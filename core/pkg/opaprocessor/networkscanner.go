package opaprocessor

import (
	"fmt"
	"time"

	servicediscovery "github.com/kubescape/kubescape-network-scanner/cmd"
)

const (
	ServiceSuffix = ".svc.cluster.local"
	Timeout       = time.Second * 3
)

// Check if the service is unauthenticated using kubescape-network-scanner.
func isUnauthenticatedService(host string, port int, namespace string) bool {
	// Skip kube-system namespace.
	if namespace == "kube-system" {
		return false
	}

	if namespace == "" {
		namespace = "default"
	}

	k8sService := fmt.Sprintf("%s.%s%s", host, namespace, ServiceSuffix)

	// Run the network scanner in a goroutine and wait for the result.
	results := make(chan bool, 1)
	go func() {
		discoveryResults, err := servicediscovery.ScanTargets(k8sService, port)
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
		return false
	}
}
