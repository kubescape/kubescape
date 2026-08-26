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
		// os.UserHomeDir resolves USERPROFILE on Windows (where HOME is
		// normally not set at all) and reports an error when there is no home
		// directory to resolve. Reading os.Getenv("HOME") instead left the
		// home path empty, so filepath.Join produced the relative path
		// ".kube/config" and the lookup silently became relative to the
		// current working directory. Skip the file-based lookup entirely when
		// there is no home directory and fall back to the in-cluster
		// configuration, as before.
		home, homeErr := os.UserHomeDir()
		if homeErr == nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube", "config"))
		}
		if homeErr != nil || err != nil {
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
