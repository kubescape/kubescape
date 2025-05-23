package mcpserver

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func CreateKsObjectConnection(namespace string, maxElapsedTime time.Duration) (spdxv1beta1.SpdxV1beta1Interface, error) {
	var cfg *rest.Config
	kubeconfig := os.Getenv("KUBECONFIG")
	// use the current context in kubeconfig, defaulting to ~/.kube/config if not set
	if kubeconfig == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			kubeconfig = fmt.Sprintf("%s/.kube/config", homeDir)
		}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
		}
	}
	// force GRPC
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	cfg.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := versioned.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create K8S Aggregated API Client with err: %v", err)
	}

	// verify storage is ready by listing ApplicationProfiles once
	if _, err := clientset.SpdxV1beta1().ApplicationProfiles("default").List(context.Background(), metav1.ListOptions{}); err != nil {
		return nil, fmt.Errorf("failed to verify storage availability: %w", err)
	}

	return clientset.SpdxV1beta1(), nil
}
