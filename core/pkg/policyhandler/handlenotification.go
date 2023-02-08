package policyhandler

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"go.opentelemetry.io/otel"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	cloudsupportv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"

	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resourcehandler"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// PolicyHandler -
type PolicyHandler struct {
	resourceHandler resourcehandler.IResourceHandler
	// we are listening on this chan in opaprocessor/processorhandler.go/ProcessRulesListener func
	getters *cautils.Getters
}

// CreatePolicyHandler Create ws-handler obj
func NewPolicyHandler(resourceHandler resourcehandler.IResourceHandler) *PolicyHandler {
	return &PolicyHandler{
		resourceHandler: resourceHandler,
	}
}

func (policyHandler *PolicyHandler) CollectResources(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo) (*cautils.OPASessionObj, error) {
	opaSessionObj := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo)

	// validate notification
	// TODO
	policyHandler.getters = &scanInfo.Getters

	// get policies
	if err := policyHandler.getPolicies(ctx, policyIdentifier, opaSessionObj); err != nil {
		return opaSessionObj, err
	}

	err := policyHandler.getResources(ctx, policyIdentifier, opaSessionObj)
	if err != nil {
		return opaSessionObj, err
	}
	if (opaSessionObj.K8SResources == nil || len(*opaSessionObj.K8SResources) == 0) && (opaSessionObj.ArmoResource == nil || len(*opaSessionObj.ArmoResource) == 0) {
		return opaSessionObj, fmt.Errorf("empty list of resources")
	}

	// update channel
	return opaSessionObj, nil
}

func (policyHandler *PolicyHandler) getResources(ctx context.Context, policyIdentifier []cautils.PolicyIdentifier, opaSessionObj *cautils.OPASessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "policyHandler.getResources")
	defer span.End()
	opaSessionObj.Report.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo(ctx)

	// set cloud metadata only when scanning a cluster
	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == reportv2.Cluster {
		setCloudMetadata(opaSessionObj)
	}

	resourcesMap, allResources, ksResources, err := policyHandler.resourceHandler.GetResources(ctx, opaSessionObj, &policyIdentifier[0].Designators)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.ArmoResource = ksResources

	return nil
}

/* unused for now
func getDesignator(policyIdentifier []cautils.PolicyIdentifier) *armotypes.PortalDesignator {
	if len(policyIdentifier) > 0 {
		return &policyIdentifier[0].Designators
	}
	return &armotypes.PortalDesignator{}
}
*/

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
