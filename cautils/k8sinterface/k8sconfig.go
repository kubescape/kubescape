package k8sinterface

import (
	"context"
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	// DO NOT REMOVE - load cloud providers auth
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var ConnectedToCluster = true

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
	var kubernetesClient *kubernetes.Clientset
	var err error

	if !IsConnectedToCluster() {
		fmt.Println(fmt.Errorf("failed to load kubernetes config: no configuration has been provided, try setting KUBECONFIG environment variable"))
		os.Exit(1)
	}

	kubernetesClient, err = kubernetes.NewForConfig(GetK8sConfig())
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
		return fmt.Errorf("failed to load kubernetes config: %s", strings.ReplaceAll(err.Error(), "KUBERNETES_MASTER", "KUBECONFIG"))
	}
	if _, err := restclient.InClusterConfig(); err == nil {
		RunningIncluster = true
	}

	K8SConfig = kubeconfig
	return nil
}

// GetK8sConfig get config. load if not loaded yet
func GetK8sConfig() *restclient.Config {
	if !IsConnectedToCluster() {
		return nil
	}
	return K8SConfig
}

func IsConnectedToCluster() bool {
	if K8SConfig == nil {
		if err := LoadK8sConfig(); err != nil {
			ConnectedToCluster = false
		}
	}
	return ConnectedToCluster
}
func GetClusterName() string {
	if !ConnectedToCluster {
		return ""
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})
	config, err := kubeConfig.RawConfig()
	if err != nil {
		return ""
	}
	// TODO - Handle if empty
	return config.CurrentContext
}

func GetDefaultNamespace() string {
	defaultNamespace := "default"
	clientCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		return defaultNamespace
	}
	apiContext, ok := clientCfg.Contexts[clientCfg.CurrentContext]
	if !ok || apiContext == nil {
		return defaultNamespace
	}
	namespace := apiContext.Namespace
	if apiContext.Namespace == "" {
		namespace = defaultNamespace
	}
	return namespace
}
