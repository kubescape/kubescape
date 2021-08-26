package policyhandler

import (
	"fmt"
	"kube-escape/cautils"

	"kube-escape/cautils/k8sinterface"

	"kube-escape/cautils/opapolicy"

	"github.com/golang/glog"
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

func (policyHandler *PolicyHandler) HandleNotificationRequest(notification *opapolicy.PolicyNotification, excludedNamespaces string) error {
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO

	// get policies
	cautils.ProgressTextDisplay("Downloading framework definitions")
	frameworks, err := policyHandler.GetPoliciesFromBackend(notification)
	if err != nil {
		return err
	}

	if len(frameworks) == 0 {
		err := fmt.Errorf("Could not download any policies, please check previous logs")
		return err
	}
	opaSessionObj.Frameworks = frameworks
	cautils.SuccessTextDisplay("Downloaded framework")
	// store policies as configmaps
	// TODO

	// get k8s resources
	cautils.ProgressTextDisplay("Accessing Kubernetes objects")
	k8sResources, err := policyHandler.getK8sResources(frameworks, &notification.Designators, excludedNamespaces)
	if err != nil || len(*k8sResources) == 0 {
		glog.Error(err)
	} else {
		cautils.SuccessTextDisplay("Accessed successfully to Kubernetes objects, let’s start!!!")
	}
	opaSessionObj.K8SResources = k8sResources

	// update channel
	*policyHandler.processPolicy <- opaSessionObj
	return nil
}
