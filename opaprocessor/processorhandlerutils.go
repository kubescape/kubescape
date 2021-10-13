package opaprocessor

import (
	"encoding/json"
	"fmt"

	pkgcautils "github.com/armosec/utils-go/utils"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/armoapi-go/opapolicy"
	"github.com/armosec/k8s-interface/k8sinterface"
	resources "github.com/armosec/opa-utils/resources"
	"github.com/open-policy-agent/opa/rego"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func getKubernetesObjects(k8sResources *cautils.K8SResources, match []opapolicy.RuleMatchObjects) []map[string]interface{} {
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
func parseRegoResult(regoResult *rego.ResultSet) ([]opapolicy.RuleResponse, error) {
	var errs error
	ruleResponses := []opapolicy.RuleResponse{}
	for _, result := range *regoResult {
		for desicionIdx := range result.Expressions {
			if resMap, ok := result.Expressions[desicionIdx].Value.(map[string]interface{}); ok {
				for objName := range resMap {
					jsonBytes, err := json.Marshal(resMap[objName])
					if err != nil {
						err = fmt.Errorf("in parseRegoResult, json.Marshal failed. name: %s, obj: %v, reason: %s", objName, resMap[objName], err)
						glog.Error(err)
						errs = fmt.Errorf("%s\n%s", errs, err)
						continue
					}
					desObj := make([]opapolicy.RuleResponse, 0)
					if err := json.Unmarshal(jsonBytes, &desObj); err != nil {
						err = fmt.Errorf("in parseRegoResult, json.Unmarshal failed. name: %s, obj: %v, reason: %s", objName, resMap[objName], err)
						glog.Error(err)
						errs = fmt.Errorf("%s\n%s", errs, err)
						continue
					}
					ruleResponses = append(ruleResponses, desObj...)
				}
			}
		}
	}
	return ruleResponses, errs
}

//editRuleResponses editing the responses -> removing duplications, clearing secret data, etc.
func editRuleResponses(ruleResponses []opapolicy.RuleResponse) []opapolicy.RuleResponse {
	uniqueRuleResponses := map[string]bool{}
	lenRuleResponses := len(ruleResponses)
	for i := 0; i < lenRuleResponses; i++ {
		for j := range ruleResponses[i].AlertObject.K8SApiObjects {
			w := k8sinterface.NewWorkloadObj(ruleResponses[i].AlertObject.K8SApiObjects[j])
			if w == nil {
				continue
			}
			resourceID := fmt.Sprintf("%s/%s/%s/%s", w.GetApiVersion(), w.GetNamespace(), w.GetKind(), w.GetName())
			if found := uniqueRuleResponses[resourceID]; found {
				// resource found -> remove from slice
				ruleResponses = removeFromSlice(ruleResponses, i)
				lenRuleResponses -= 1
				break
			} else {
				cleanRuleResponses(w)
				ruleResponses[i].AlertObject.K8SApiObjects[j] = w.GetWorkload()
				uniqueRuleResponses[resourceID] = true
			}
		}
	}
	return ruleResponses
}
func cleanRuleResponses(workload k8sinterface.IWorkload) {
	if workload.GetKind() == "Secret" {
		workload.RemoveSecretData()
	}
}

func removeFromSlice(ruleResponses []opapolicy.RuleResponse, i int) []opapolicy.RuleResponse {
	if i != len(ruleResponses)-1 {
		ruleResponses[i] = ruleResponses[len(ruleResponses)-1]
	}

	return ruleResponses[:len(ruleResponses)-1]
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

func listMatchKinds(match []opapolicy.RuleMatchObjects) []string {
	matchKinds := []string{}
	for i := range match {
		matchKinds = append(matchKinds, match[i].Resources...)
	}
	return matchKinds
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
