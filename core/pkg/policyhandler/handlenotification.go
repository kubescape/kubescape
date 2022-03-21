package policyhandler

import (
	"fmt"

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

func (policyHandler *PolicyHandler) getResources(notification *reporthandling.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) error {
	opaSessionObj.Report.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()

	scanInfoToScanMetadata(opaSessionObj, scanInfo)

	resourcesMap, allResources, armoResources, err := policyHandler.resourceHandler.GetResources(opaSessionObj, &notification.Designators)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources
	opaSessionObj.ArmoResource = armoResources

	return nil
}

func scanInfoToScanMetadata(opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) {
	opaSessionObj.Metadata.ClusterMetadata.ContextName = k8sinterface.GetClusterName()
	opaSessionObj.Metadata.ScanMetadata.Format = scanInfo.Format
	opaSessionObj.Metadata.ScanMetadata.Submit = scanInfo.Submit

	// TODO - Add excluded and included namespaces
	// if len(scanInfo.ExcludedNamespaces) > 1 {
	// 	opaSessionObj.Metadata.ScanMetadata.ExcludedNamespaces = strings.Split(scanInfo.ExcludedNamespaces[1:], ",")
	// }
	// if len(scanInfo.IncludeNamespaces) > 1 {
	// 	opaSessionObj.Metadata.ScanMetadata.IncludeNamespaces = strings.Split(scanInfo.IncludeNamespaces[1:], ",")
	// }

	// scan type
	if len(scanInfo.PolicyIdentifier) > 0 {
		opaSessionObj.Metadata.ScanMetadata.TargetType = string(scanInfo.PolicyIdentifier[0].Kind)
	}
	// append frameworks
	for _, policy := range scanInfo.PolicyIdentifier {
		opaSessionObj.Metadata.ScanMetadata.TargetNames = append(opaSessionObj.Metadata.ScanMetadata.TargetNames, policy.Name)
	}
	opaSessionObj.Metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	opaSessionObj.Metadata.ScanMetadata.FailThreshold = scanInfo.FailThreshold
	opaSessionObj.Metadata.ScanMetadata.HostScanner = scanInfo.HostSensorEnabled.GetBool()
	opaSessionObj.Metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	opaSessionObj.Metadata.ScanMetadata.ControlsInputs = scanInfo.ControlsInputs
}
