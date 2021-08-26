package policyhandler

import (
	"fmt"
	"kube-escape/cautils"

	"kube-escape/cautils/k8sinterface"

	"kube-escape/cautils/opapolicy"
)

// PolicyHandler -
type PolicyHandler struct {
	k8s *k8sinterface.KubernetesApi
	// we are listening on this chan in opaprocessor/processorhandler.go/ProcessRulesListenner func
	processPolicy *chan *cautils.OPASessionObj
}

// CreatePolicyHandler Create ws-handler obj
func NewPolicyHandler(processPolicy *chan *cautils.OPASessionObj, k8s *k8sinterface.KubernetesApi) *PolicyHandler {
	return &PolicyHandler{
		k8s:           k8s,
		processPolicy: processPolicy,
	}
}

func (policyHandler *PolicyHandler) HandleNotificationRequest(notification *opapolicy.PolicyNotification, scanInfo *opapolicy.ScanInfo) error {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO

	// get policies
	frameworks, err := policyHandler.getPolicies(notification)
	if err != nil {
		return err
	}
	if len(frameworks) == 0 {
		return fmt.Errorf("empty list of frameworks")
	}
	opaSessionObj.Frameworks = frameworks

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

func (policyHandler *PolicyHandler) getPolicies(notification *opapolicy.PolicyNotification) ([]opapolicy.Framework, error) {

	cautils.ProgressTextDisplay("Downloading framework definitions")

	// TODO - support load policies from local file
	frameworks, err := policyHandler.GetPoliciesFromBackend(notification)
	if err != nil {
		return frameworks, err
	}

	if len(frameworks) == 0 {
		err := fmt.Errorf("could not download any policies, please check previous logs")
		return frameworks, err
	}
	cautils.SuccessTextDisplay("Downloaded framework")

	return frameworks, nil
}

func (policyHandler *PolicyHandler) getResources(notification *opapolicy.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *opapolicy.ScanInfo) (*cautils.K8SResources, error) {
	var k8sResources *cautils.K8SResources
	var err error
	if len(scanInfo.InputPatterns) > 0 {
		k8sResources, err = policyHandler.loadResources(opaSessionObj.Frameworks, scanInfo)
	} else {
		k8sResources, err = policyHandler.getK8sResources(opaSessionObj.Frameworks, &notification.Designators, scanInfo.ExcludedNamespaces)

	}

	return k8sResources, err
}
