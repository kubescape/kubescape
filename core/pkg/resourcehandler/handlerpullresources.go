package resourcehandler

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudsupportv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/opaprocessor"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"go.opentelemetry.io/otel"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func CollectResources(ctx context.Context, rsrcHandler IResourceHandler, policyIdentifier []cautils.PolicyIdentifier, opaSessionObj *cautils.OPASessionObj, progressListener opaprocessor.IJobProgressNotificationClient) error {
	ctx, span := otel.Tracer("").Start(ctx, "resourcehandler.CollectResources")
	defer span.End()
	opaSessionObj.Report.ClusterAPIServerInfo = rsrcHandler.GetClusterAPIServerInfo(ctx)

	// set cloud metadata only when scanning a cluster
	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reportv2.Cluster {
		setCloudMetadata(opaSessionObj)
	}

	resourcesMap, allResources, ksResources, excludedRulesMap, err := rsrcHandler.GetResources(ctx, opaSessionObj, progressListener)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.KubescapeResource = ksResources
	opaSessionObj.ExcludedRules = excludedRulesMap

	if (opaSessionObj.K8SResources == nil || len(opaSessionObj.K8SResources) == 0) && (opaSessionObj.KubescapeResource == nil || len(opaSessionObj.KubescapeResource) == 0) {
		return fmt.Errorf("empty list of resources")
	}

	return nil
}

func setCloudMetadata(opaSessionObj *cautils.OPASessionObj) {
	iCloudMetadata := getCloudMetadata(opaSessionObj, k8sinterface.GetConfig())
	if iCloudMetadata == nil {
		return
	}
	cloudMetadata := reportv2.NewCloudMetadata(iCloudMetadata)
	opaSessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudMetadata = cloudMetadata
	opaSessionObj.Metadata.ClusterMetadata.CloudMetadata = cloudMetadata             // deprecated - fallback
	opaSessionObj.Report.ClusterCloudProvider = iCloudMetadata.Provider().ToString() // deprecated - fallback

	logger.L().Debug("Cloud metadata", helpers.String("provider", iCloudMetadata.Provider().ToString()), helpers.String("name", iCloudMetadata.GetName()))
}

// getCloudMetadata - get cloud metadata from kubeconfig or API server
// There are 3 options:
// 1. Get cloud provider from API server git version (EKS, GKE)
// 2. Get cloud provider from kubeconfig by parsing the cluster context (EKS, GKE)
// 3. Get cloud provider from kubeconfig by parsing the server URL (AKS)
func getCloudMetadata(opaSessionObj *cautils.OPASessionObj, config *clientcmdapi.Config) apis.ICloudParser {

	if config == nil {
		return nil
	}

	var provider string

	// attempting to get cloud provider from API server git version
	if opaSessionObj.Report.ClusterAPIServerInfo != nil {
		provider = cloudsupport.GetCloudProvider(opaSessionObj.Report.ClusterAPIServerInfo.GitVersion)
	}

	if provider == cloudsupportv1.AKS || isAKS(config) {
		return helpersv1.NewAKSMetadata(k8sinterface.GetContextName())
	}
	if provider == cloudsupportv1.EKS || isEKS(config) {
		return helpersv1.NewEKSMetadata(k8sinterface.GetContextName())
	}
	if provider == cloudsupportv1.GKE || isGKE(config) {
		return helpersv1.NewGKEMetadata(k8sinterface.GetContextName())
	}

	return nil
}

// check if the server is AKS. e.g. https://XXX.XX.XXX.azmk8s.io:443
func isAKS(config *clientcmdapi.Config) bool {
	const serverIdentifierAKS = "azmk8s.io"
	if cluster, ok := config.Clusters[k8sinterface.GetContextName()]; ok {
		return strings.Contains(cluster.Server, serverIdentifierAKS)
	}
	return false
}

// check if the server is EKS. e.g. arn:aws:eks:eu-west-1:xxx:cluster/xxxx
func isEKS(config *clientcmdapi.Config) bool {
	if context, ok := config.Contexts[k8sinterface.GetContextName()]; ok {
		return strings.Contains(context.Cluster, cloudsupportv1.EKS)
	}
	return false
}

// check if the server is GKE. e.g. gke_xxx-xx-0000_us-central1-c_xxxx-1
func isGKE(config *clientcmdapi.Config) bool {
	if context, ok := config.Contexts[k8sinterface.GetContextName()]; ok {
		return strings.Contains(context.Cluster, cloudsupportv1.GKE)
	}
	return false
}
