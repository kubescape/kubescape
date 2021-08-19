package k8sinterface

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	// DO NOT REMOVE - load cloud providers auth
	_ "k8s.io/client-go/plugin/pkg/client/auth"
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

var ConfigPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
var RunningIncluster bool

// LoadK8sConfig load config from local file or from cluster
func LoadK8sConfig() error {
	kubeconfig, err := clientcmd.BuildConfigFromFlags("", ConfigPath)
	if err != nil {
		// kubeconfig, err = restclient.InClusterConfig()
		// if err != nil {
		return fmt.Errorf("Failed to load kubernetes config from file: '%s'.\n", ConfigPath)
		// }
		// RunningIncluster = true
	} else {
		RunningIncluster = false
	}
	K8SConfig = kubeconfig
	return nil
}

// GetK8sConfig get config. load if not loaded yer
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
