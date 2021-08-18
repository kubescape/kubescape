package policyhandler

import (
	"flag"
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

func (policyHandler *PolicyHandler) HandleNotificationRequest(notification *opapolicy.PolicyNotification) error {
	glog.Infof("Processing notification. reportID: %s", notification.ReportID)
	opaSessionObj := cautils.NewOPASessionObj(nil, nil)
	// validate notification
	// TODO

	// get policies
	glog.Infof(fmt.Sprintf("Getting %d policies from backend. reportID: %s", len(notification.Rules), notification.ReportID))
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
	glog.Infof(fmt.Sprintf("Getting kubernetes objects. reportID: %s", notification.ReportID))
	excludedNamespaces := ""
	if flag.Arg(3) == "--exclude-namespaces" {
		excludedNamespaces = flag.Arg(4)
	}
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
