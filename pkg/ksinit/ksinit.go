package ksinit

import (
	"os"
	"path/filepath"
	"time"

	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CreateKsObjectConnection initializes a KS object connection, shared by mcpserver and httphandler
func CreateKsObjectConnection(namespace string, maxElapsedTime time.Duration) (spdxv1beta1.SpdxV1beta1Interface, error) {
	var cfg *rest.Config
	var err error

	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		home := os.Getenv("HOME")
		kubeconfigPath := filepath.Join(home, ".kube", "config")
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			cfg, err = rest.InClusterConfig()
		}
	}
	if err != nil {
		return nil, err
	}

	// disable rate limiting
	cfg.QPS = 0
	cfg.RateLimiter = nil
	// force GRPC
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	cfg.ContentType = "application/vnd.kubernetes.protobuf"

	return spdxv1beta1.NewForConfig(cfg)
}
