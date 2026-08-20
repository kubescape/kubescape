package mcpserver

import (
	"time"

	"github.com/kubescape/kubescape/v3/pkg/ksinit"

	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
)

// CreateKsObjectConnection delegates to the shared ksinit package
func CreateKsObjectConnection(namespace string, maxElapsedTime time.Duration) (spdxv1beta1.SpdxV1beta1Interface, error) {
	return ksinit.CreateKsObjectConnection(namespace, maxElapsedTime)
}
