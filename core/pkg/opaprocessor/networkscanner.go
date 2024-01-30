package opaprocessor

import (
	"fmt"

	servicediscovery "github.com/kubescape/kubescape-network-scanner/cmd"
)

const (
	ServiceSuffix = ".svc.cluster.local"
)

// Check if the service is unauthenticated using kubescape-network-scanner.
func isUnauthenticatedService(host string, port int, namespace string) bool {
	if namespace == "kube-system" {
		return false
	}

	if namespace == "" {
		namespace = "default"
	}

	k8sService := fmt.Sprintf("%s.%s%s", host, namespace, ServiceSuffix)

	discoveryResults, err := servicediscovery.ScanTargets(k8sService, port)
	if err != nil {
		return false
	}

	if !discoveryResults.IsAuthenticated && discoveryResults.ApplicationLayer != "" {
		return true
	}

	return false
}
