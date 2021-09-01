package policyhandler

import (
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"

	"github.com/armosec/kubescape/cautils/k8sinterface"

	"github.com/armosec/kubescape/cautils/opapolicy"
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

func (policyHandler *PolicyHandler) HandleNotificationRequest(notification *opapolicy.PolicyNotification, scanInfo *cautils.ScanInfo) error {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO

	// get policies
	frameworks, err := policyHandler.getPolicies(notification, scanInfo.PolicyGetter)
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

func (policyHandler *PolicyHandler) getPolicies(notification *opapolicy.PolicyNotification, policyGetter getter.IPolicyGetter) ([]opapolicy.Framework, error) {

	cautils.ProgressTextDisplay("Downloading/Loading framework definitions")

	// TODO - support load policies from local file
	frameworks, err := policyHandler.GetPoliciesFromBackend(notification, policyGetter)
	if err != nil {
		return frameworks, err
	}

	if len(frameworks) == 0 {
		err := fmt.Errorf("could not download any policies, please check previous logs")
		return frameworks, err
	}
	cautils.SuccessTextDisplay("Downloaded/Loaded framework")

	return frameworks, nil
}

func (policyHandler *PolicyHandler) getResources(notification *opapolicy.PolicyNotification, opaSessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (*cautils.K8SResources, error) {
	var k8sResources *cautils.K8SResources
	var err error
	if scanInfo.ScanRunningCluster() {
		k8sResources, err = policyHandler.getK8sResources(opaSessionObj.Frameworks, &notification.Designators, scanInfo.ExcludedNamespaces)
	} else {
		k8sResources, err = policyHandler.loadResources(opaSessionObj.Frameworks, scanInfo)
	}

	return k8sResources, err
}
