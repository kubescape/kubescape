package opaprocessor

import (
	pkgcautils "github.com/armosec/utils-go/utils"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
	resources "github.com/armosec/opa-utils/resources"

	"github.com/golang/glog"
)

func getKubernetesObjects(k8sResources *cautils.K8SResources, match []reporthandling.RuleMatchObjects) []workloadinterface.IMetadata {
	k8sObjects := []workloadinterface.IMetadata{}
	for m := range match {
		for _, groups := range match[m].APIGroups {
			for _, version := range match[m].APIVersions {
				for _, resource := range match[m].Resources {
					groupResources := k8sinterface.ResourceGroupToString(groups, version, resource)
					for _, groupResource := range groupResources {
						if k8sObj, ok := (*k8sResources)[groupResource]; ok {
							if k8sObj == nil {
								continue
								// glog.Errorf("Resource '%s' is nil, probably failed to pull the resource", groupResource)
							}
							k8sObjects = append(k8sObjects, k8sObj...)
						}
					}
				}
			}
		}
	}

	return k8sObjects
}

func getRuleDependencies() (map[string]string, error) {
	modules := resources.LoadRegoModules()
	if len(modules) == 0 {
		glog.Warningf("failed to load rule dependencies")
	}
	return modules, nil
}

//editRuleResponses editing the responses -> removing duplications, clearing secret data, etc.
func editRuleResponses(ruleResponses []reporthandling.RuleResponse) []reporthandling.RuleResponse {
	lenRuleResponses := len(ruleResponses)
	for i := 0; i < lenRuleResponses; i++ {
		for j := range ruleResponses[i].AlertObject.K8SApiObjects {
			w := workloadinterface.NewWorkloadObj(ruleResponses[i].AlertObject.K8SApiObjects[j])
			if w == nil {
				continue
			}

			cleanRuleResponses(w)
			ruleResponses[i].AlertObject.K8SApiObjects[j] = w.GetWorkload()
		}
	}
	return ruleResponses
}
func cleanRuleResponses(workload k8sinterface.IWorkload) {
	if workload.GetKind() == "Secret" {
		workload.RemoveSecretData()
	}
}

func ruleWithArmoOpaDependency(annotations map[string]interface{}) bool {
	if annotations == nil {
		return false
	}
	if s, ok := annotations["armoOpa"]; ok { // TODO - make global
		return pkgcautils.StringToBool(s.(string))
	}
	return false
}

func isRuleKubescapeVersionCompatible(rule *reporthandling.PolicyRule) bool {
	if from, ok := rule.Attributes["useFromKubescapeVersion"]; ok {
		if cautils.BuildNumber != "" {
			if from.(string) > cautils.BuildNumber {
				return false
			}
		}
	}
	if until, ok := rule.Attributes["useUntilKubescapeVersion"]; ok {
		if cautils.BuildNumber != "" {
			if until.(string) <= cautils.BuildNumber {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func removeData(obj workloadinterface.IMetadata) {
	if !workloadinterface.IsTypeWorkload(obj.GetObject()) {
		return // remove data only from kubernetes objects
	}
	workload := workloadinterface.NewWorkloadObj(obj.GetObject())
	switch workload.GetKind() {
	case "Secret":
		removeSecretData(obj)
	case "ConfigMap":
		removeConfigMapData(obj)
	default:
		removePodData(obj)
	}
}

func removeConfigMapData(obj workloadinterface.IMetadata) {
	if !workloadinterface.IsTypeWorkload(obj.GetObject()) {
		return // remove data only from kubernetes objects
	}
	workload := workloadinterface.NewWorkloadObj(obj.GetObject())
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "data")

}
func removeSecretData(obj workloadinterface.IMetadata) {
	if !workloadinterface.IsTypeWorkload(obj.GetObject()) {
		return // remove data only from kubernetes objects
	}
	workloadinterface.NewWorkloadObj(obj.GetObject()).RemoveSecretData()

}
func removePodData(obj workloadinterface.IMetadata) {
	if !workloadinterface.IsTypeWorkload(obj.GetObject()) {
		return // remove data only from kubernetes objects
	}
	workload := workloadinterface.NewWorkloadObj(obj.GetObject())
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")

	containers, err := workload.GetContainers()
	if err != nil || len(containers) == 0 {
		return
	}
	for i := range containers {
		for j := range containers[i].Env {
			containers[i].Env[j].Value = ""
		}
	}
	workloadinterface.SetInMap(workload.GetObject(), workloadinterface.PodSpec(workload.GetKind()), "containers", containers)
}
