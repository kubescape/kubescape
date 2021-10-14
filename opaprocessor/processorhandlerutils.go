package opaprocessor

import (
	pkgcautils "github.com/armosec/utils-go/utils"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/opa-utils/reporthandling"
	resources "github.com/armosec/opa-utils/resources"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func getKubernetesObjects(k8sResources *cautils.K8SResources, match []reporthandling.RuleMatchObjects) []map[string]interface{} {
	k8sObjects := []map[string]interface{}{}
	for m := range match {
		for _, groups := range match[m].APIGroups {
			for _, version := range match[m].APIVersions {
				for _, resource := range match[m].Resources {
					groupResources := k8sinterface.ResourceGroupToString(groups, version, resource)
					for _, groupResource := range groupResources {
						if k8sObj, ok := (*k8sResources)[groupResource]; ok {
							if k8sObj == nil {
								// glog.Errorf("Resource '%s' is nil, probably failed to pull the resource", groupResource)
							} else if v, k := k8sObj.([]map[string]interface{}); k {
								k8sObjects = append(k8sObjects, v...)
							} else if v, k := k8sObj.(map[string]interface{}); k {
								k8sObjects = append(k8sObjects, v)
							} else if v, k := k8sObj.([]unstructured.Unstructured); k {
								k8sObjects = append(k8sObjects, k8sinterface.ConvertUnstructuredSliceToMap(v)...) //
							} else {
								glog.Errorf("In 'getKubernetesObjects' resource '%s' unknown type", groupResource)
							}
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
			w := k8sinterface.NewWorkloadObj(ruleResponses[i].AlertObject.K8SApiObjects[j])
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

func percentage(big, small int) int {
	if big == 0 {
		if small == 0 {
			return 100
		}
		return 0
	}
	return int(float64(float64(big-small)/float64(big)) * 100)
}
