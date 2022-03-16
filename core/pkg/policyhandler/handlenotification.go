package policyhandler

import (
	"fmt"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/pkg/resourcehandler"
	"github.com/armosec/opa-utils/reporthandling"
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

func (policyHandler *PolicyHandler) CollectResources(notification *reporthandling.PolicyNotification, scanInfo *cautils.ScanInfo) (*cautils.OPASessionObj, error) {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO
	policyHandler.getters = &scanInfo.Getters

	// get policies
	if err := policyHandler.getPolicies(notification, opaSessionObj); err != nil {
		return opaSessionObj, err
	}

	err := policyHandler.getResources(notification, opaSessionObj, scanInfo)
	if err != nil {
		return opaSessionObj, err
	}
	if opaSessionObj.K8SResources == nil || len(*opaSessionObj.K8SResources) == 0 {
		return opaSessionObj, fmt.Errorf("empty list of resources")
	}

	// update channel
	return opaSessionObj, nil
}

func setOpaSessionObj(opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) {
	opaSessionObj.Metadata.ClusterMetadata.ContextName = k8sinterface.GetCurrentContext().Cluster
	opaSessionObj.Metadata.ScanMetadata.Format = scanInfo.Format
	opaSessionObj.Metadata.ScanMetadata.Submit = scanInfo.Submit
	opaSessionObj.Metadata.ScanMetadata.ExcludedNamespaces = strings.Split(scanInfo.ExcludedNamespaces, ",")
	opaSessionObj.Metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	opaSessionObj.Metadata.ScanMetadata.FailThreshold = scanInfo.FailThreshold
	opaSessionObj.Metadata.ScanMetadata.HostScanner = *scanInfo.HostSensorEnabled.Get()
	opaSessionObj.Metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	opaSessionObj.Metadata.ScanMetadata.ControlsInputs = scanInfo.ControlsInputs
}

func (policyHandler *PolicyHandler) getResources(notification *reporthandling.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) error {
	opaSessionObj.Report.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()
	setOpaSessionObj(opaSessionObj, scanInfo)

	resourcesMap, allResources, armoResources, err := policyHandler.resourceHandler.GetResources(opaSessionObj, &notification.Designators, scanInfo)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.ArmoResource = armoResources

	return nil
}
