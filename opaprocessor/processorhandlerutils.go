package opaprocessor

import (
	"kube-escape/cautils"

	"kube-escape/cautils/k8sinterface"
	"kube-escape/cautils/opapolicy"
	resources "kube-escape/cautils/opapolicy/resources"

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
								glog.Errorf("Resource '%s' is nil, probably failed to pull the resource", groupResource)
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
