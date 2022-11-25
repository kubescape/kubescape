package policyhandler

import (
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resourcehandler"
)

// PolicyHandler -
type PolicyHandler struct {
	resourceHandler resourcehandler.IResourceHandler
	// we are listening on this chan in opaprocessor/processorhandler.go/ProcessRulesListenner func
	getters *cautils.Getters
}

// CreatePolicyHandler Create ws-handler obj
func NewPolicyHandler(resourceHandler resourcehandler.IResourceHandler) *PolicyHandler {
	return &PolicyHandler{
		resourceHandler: resourceHandler,
	}
}

func (policyHandler *PolicyHandler) CollectResources(policyIdentifier []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo) (*cautils.OPASessionObj, error) {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil, scanInfo)

	// validate notification
	// TODO
	policyHandler.getters = &scanInfo.Getters

	// get policies
	if err := policyHandler.getPolicies(policyIdentifier, opaSessionObj); err != nil {
		return opaSessionObj, err
	}

	err := policyHandler.getResources(policyIdentifier, opaSessionObj, scanInfo)
	if err != nil {
		return opaSessionObj, err
	}
	if (opaSessionObj.K8SResources == nil || len(*opaSessionObj.K8SResources) == 0) && (opaSessionObj.ArmoResource == nil || len(*opaSessionObj.ArmoResource) == 0) {
		return opaSessionObj, fmt.Errorf("empty list of resources")
	}

	// update channel
	return opaSessionObj, nil
}

func (policyHandler *PolicyHandler) getResources(policyIdentifier []cautils.PolicyIdentifier, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) error {
	opaSessionObj.Report.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()

	// attempting to get cloud provider from API server git version
	if opaSessionObj.Report.ClusterAPIServerInfo != nil {
		opaSessionObj.Report.ClusterCloudProvider = cloudsupport.GetCloudProvider(opaSessionObj.Report.ClusterAPIServerInfo.GitVersion)
	}

	// if didn't succeed getting cloud provider from API server git version, try from context.
	if opaSessionObj.Report.ClusterCloudProvider == "" {
		clusterName := k8sinterface.GetContextName()
		opaSessionObj.Report.ClusterCloudProvider = cloudsupport.GetCloudProvider(clusterName)
	}

	resourcesMap, allResources, ksResources, err := policyHandler.resourceHandler.GetResources(opaSessionObj, &policyIdentifier[0].Designators)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.ArmoResource = ksResources

	return nil
}

func getDesignator(policyIdentifier []cautils.PolicyIdentifier) *armotypes.PortalDesignator {
	if len(policyIdentifier) > 0 {
		return &policyIdentifier[0].Designators
	}
	return &armotypes.PortalDesignator{}
}
