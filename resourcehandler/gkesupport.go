package resourcehandler

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
)

type GKEProviderEnvVar struct {
}

func NewGKEProviderEnvVar() *GKEProviderEnvVar {
	return &GKEProviderEnvVar{}
}
func (gkeProvider *GKEProviderEnvVar) getKubeClusterName() string {
	return gkeProvider.getKubeCluster()
}

func (gkeProvider *GKEProviderEnvVar) getKubeCluster() string {
	val, present := os.LookupEnv(KS_KUBE_CLUSTER_ENV_VAR)
	if present {
		return val
	}
	return ""
}

func (gkeProvider *GKEProviderEnvVar) getRegion(cluster string, provider string) (string, error) {
	return gkeProvider.getRegionForGKE(cluster)
}

func (gkeProvider *GKEProviderEnvVar) getProject(cluster string, provider string) (string, error) {
	return gkeProvider.getProjectForGKE(cluster)
}

func (gkeProvider *GKEProviderEnvVar) getProjectForGKE(cluster string) (string, error) {
	project, present := os.LookupEnv(KS_GKE_PROJECT_ENV_VAR)
	if present {
		return project, nil
	}
	parsedName := strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return "", fmt.Errorf("error: failed to parse cluster name")
	}
	project = parsedName[1]
	return project, nil
}

func (gkeProvider *GKEProviderEnvVar) getRegionForGKE(cluster string) (string, error) {
	region, present := os.LookupEnv(KS_CLOUD_REGION_ENV_VAR)
	if present {
		return region, nil
	}
	parsedName := strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return "", fmt.Errorf("error: failed to parse cluster name")
	}
	region = parsedName[2]
	return region, nil

}

// ------------------------------ GKEProviderContext --------------------------------------------------------

type GKEProviderContext struct {
}

func NewGKEProviderContext() *GKEProviderContext {
	return &GKEProviderContext{}
}

func (gkeProviderContext *GKEProviderContext) getKubeClusterName() string {
	context := k8sinterface.GetCurrentContext()
	if context == nil {
		return ""
	}
	cluster := context.Cluster
	parsedName := strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return ""
	}
	clusterName := parsedName[3]
	if clusterName != "" {
		return clusterName
	}
	cluster = k8sinterface.GetClusterName()
	parsedName = strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return ""
	}
	clusterName = parsedName[3]
	return clusterName
}

func (gkeProviderContext *GKEProviderContext) getKubeCluster() string {
	context := k8sinterface.GetCurrentContext()
	if context == nil {
		return ""
	}
	cluster := context.Cluster
	if cluster != "" {
		return cluster
	}
	return k8sinterface.GetClusterName()

}

func (gkeProviderContext *GKEProviderContext) getRegion(cluster string, provider string) (string, error) {
	return gkeProviderContext.getRegionForGKE(cluster)
}

func (gkeProviderContext *GKEProviderContext) getProject(cluster string, provider string) (string, error) {
	return gkeProviderContext.getProjectForGKE(cluster)
}

func (gkeProviderContext *GKEProviderContext) getProjectForGKE(cluster string) (string, error) {
	parsedName := strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return "", fmt.Errorf("error: failed to parse cluster name")
	}
	project := parsedName[1]
	return project, nil
}

func (gkeProviderContext *GKEProviderContext) getRegionForGKE(cluster string) (string, error) {
	parsedName := strings.Split(cluster, "_")
	if len(parsedName) < 3 {
		return "", fmt.Errorf("error: failed to parse cluster name")
	}
	region := parsedName[2]
	return region, nil
}
