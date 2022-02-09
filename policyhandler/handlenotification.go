package policyhandler

import (
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/opa-utils/reporthandling"
)

// PolicyHandler -
type PolicyHandler struct {
	resourceHandler resourcehandler.IResourceHandler
	// we are listening on this chan in opaprocessor/processorhandler.go/ProcessRulesListenner func
	processPolicy *chan *cautils.OPASessionObj
	getters       *cautils.Getters
}

// CreatePolicyHandler Create ws-handler obj
func NewPolicyHandler(processPolicy *chan *cautils.OPASessionObj, resourceHandler resourcehandler.IResourceHandler) *PolicyHandler {
	return &PolicyHandler{
		resourceHandler: resourceHandler,
		processPolicy:   processPolicy,
	}
}

func (policyHandler *PolicyHandler) HandleNotificationRequest(notification *reporthandling.PolicyNotification, scanInfo *cautils.ScanInfo) error {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO
	policyHandler.getters = &scanInfo.Getters

	// get policies
	if err := policyHandler.getPolicies(notification, opaSessionObj); err != nil {
		return err
	}

	err := policyHandler.getResources(notification, opaSessionObj, scanInfo)
	if err != nil {
		return err
	}
	if opaSessionObj.K8SResources == nil || len(*opaSessionObj.K8SResources) == 0 {
		return fmt.Errorf("empty list of resources")
	}

	// update channel
	*policyHandler.processPolicy <- opaSessionObj
	return nil
}

func (policyHandler *PolicyHandler) getResources(notification *reporthandling.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) error {

	opaSessionObj.Report.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()
	resourcesMap, allResources, err := policyHandler.resourceHandler.GetResources(opaSessionObj.Frameworks, &notification.Designators)
	if err != nil {
		return err
	}

	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources

	return nil
}
