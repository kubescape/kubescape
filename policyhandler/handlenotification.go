package policyhandler

import (
	"fmt"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/hostsensorutils"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/opa-utils/reporthandling"
)

// PolicyHandler -
type PolicyHandler struct {
	resourceHandler   resourcehandler.IResourceHandler
	hostSensorHandler hostsensorutils.IHostSensor
	// we are listening on this chan in opaprocessor/processorhandler.go/ProcessRulesListenner func
	processPolicy *chan *cautils.OPASessionObj
	getters       *cautils.Getters
}

// CreatePolicyHandler Create ws-handler obj
func NewPolicyHandler(processPolicy *chan *cautils.OPASessionObj, resourceHandler resourcehandler.IResourceHandler, hostSensorHandler hostsensorutils.IHostSensor) *PolicyHandler {
	return &PolicyHandler{
		resourceHandler:   resourceHandler,
		processPolicy:     processPolicy,
		hostSensorHandler: hostSensorHandler,
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
	resourcesMap, err := policyHandler.resourceHandler.GetResources(opaSessionObj.Frameworks, &notification.Designators)
	if err != nil {
		return resourcesMap, err
	}
	hostResources, err := policyHandler.hostSensorHandler.CollectResources()
	if err != nil {
		return resourcesMap, err
	}
	for rscIdx := range hostResources {
		groupResources := k8sinterface.ResourceGroupToString(hostResources[rscIdx].Group, hostResources[rscIdx].GetApiVersion(), hostResources[rscIdx].GetKind())
		for _, groupResource := range groupResources {
			grpReasorceList, ok := (*resourcesMap)[groupResource]
			if !ok {
				grpReasorceList = make([]workloadinterface.IMetadata, 0)
			}
			grpReasorceList = append(grpReasorceList, &hostResources[rscIdx])
			(*resourcesMap)[groupResource] = grpReasorceList
		}
	}
	cautils.SuccessTextDisplay("Let’s start!!!")
	return resourcesMap, nil
}
