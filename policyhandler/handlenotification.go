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

	opaSessionObj.PostureReport.ClusterAPIServerInfo = policyHandler.resourceHandler.GetClusterAPIServerInfo()
	resourcesMap, allResources, err := policyHandler.resourceHandler.GetResources(opaSessionObj.Frameworks, &notification.Designators)
	if err != nil {
		return err
	}

	if err := policyHandler.collectHostResources(allResources, resourcesMap); err != nil {
		return err
	}
	opaSessionObj.K8SResources = resourcesMap
	opaSessionObj.AllResources = allResources

	cautils.SuccessTextDisplay("Let’s start!!!")
	return nil
}

func (policyHandler *PolicyHandler) collectHostResources(allResources map[string]workloadinterface.IMetadata, resourcesMap *cautils.K8SResources) error {
	hostResources, err := policyHandler.hostSensorHandler.CollectResources()
	if err != nil {
		return err
	}
	for rscIdx := range hostResources {
		groupResources := k8sinterface.ResourceGroupToString(hostResources[rscIdx].Group, hostResources[rscIdx].GetApiVersion(), hostResources[rscIdx].GetKind())
		for _, groupResource := range groupResources {
			allResources[hostResources[rscIdx].GetID()] = &hostResources[rscIdx]

			grpResourceList, ok := (*resourcesMap)[groupResource]
			if !ok {
				grpResourceList = make([]string, 0)
			}
			(*resourcesMap)[groupResource] = append(grpResourceList, hostResources[rscIdx].GetID())
		}
	}
	return nil
}
