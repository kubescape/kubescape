package k8sinterface

import (
	"context"
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	// DO NOT REMOVE - load cloud providers auth
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// K8SConfig pointer to k8s config
var K8SConfig *restclient.Config

// KubernetesApi -
type KubernetesApi struct {
	KubernetesClient kubernetes.Interface
	DynamicClient    dynamic.Interface
	Context          context.Context
}

// NewKubernetesApi -
func NewKubernetesApi() *KubernetesApi {

	kubernetesClient, err := kubernetes.NewForConfig(GetK8sConfig())
	if err != nil {
		fmt.Printf("Failed to load config file, reason: %s", err.Error())
		os.Exit(1)
	}
	dynamicClient, err := dynamic.NewForConfig(K8SConfig)
	if err != nil {
		fmt.Printf("Failed to load config file, reason: %s", err.Error())
		os.Exit(1)
	}

	return &KubernetesApi{
		KubernetesClient: kubernetesClient,
		DynamicClient:    dynamicClient,
		Context:          context.Background(),
	}
}

// RunningIncluster whether running in cluster
var RunningIncluster bool

// LoadK8sConfig load config from local file or from cluster
func LoadK8sConfig() error {
	kubeconfig, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubernetes config: %s\n", strings.ReplaceAll(err.Error(), "KUBERNETES_MASTER", "KUBECONFIG"))
	}
	if _, err := restclient.InClusterConfig(); err == nil {
		RunningIncluster = true
	}
	K8SConfig = kubeconfig
	return nil
}

// GetK8sConfig get config. load if not loaded yet
func GetK8sConfig() *restclient.Config {
	if K8SConfig == nil {
		if err := LoadK8sConfig(); err != nil {
			// print error
			fmt.Printf("%s", err.Error())
			os.Exit(1)
		}
	}
	return K8SConfig
}
