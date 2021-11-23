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

	k8sResources, err := policyHandler.getResources(notification, opaSessionObj, scanInfo)
	if err != nil {
		return err
	}
	if k8sResources == nil || len(*k8sResources) == 0 {
		return fmt.Errorf("empty list of resources")
	}
	opaSessionObj.K8SResources = k8sResources

	// update channel
	*policyHandler.processPolicy <- opaSessionObj
	return nil
}

func (policyHandler *PolicyHandler) getResources(notification *reporthandling.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (*cautils.K8SResources, error) {

	opaSessionObj.PostureReport.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()
	return policyHandler.resourceHandler.GetResources(opaSessionObj.Frameworks, &notification.Designators)
}
