package policyhandler

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"

	"github.com/armosec/k8s-interface/k8sinterface"
)

func setResourceMap(frameworks []reporthandling.Framework) *cautils.K8SResources {
	k8sResources := make(cautils.K8SResources)
	complexMap := setComplexResourceMap(frameworks)
	for group := range complexMap {
		for version := range complexMap[group] {
			for resource := range complexMap[group][version] {
				groupResources := k8sinterface.ResourceGroupToString(group, version, resource)
				for _, groupResource := range groupResources {
					k8sResources[groupResource] = nil
				}
			}
		}
	}
	return &k8sResources
}

func convertComplexResourceMap(frameworks []reporthandling.Framework) map[string]map[string]map[string]interface{} {
	k8sResources := make(map[string]map[string]map[string]interface{})
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				for _, match := range rule.Match {
					insertK8sResources(k8sResources, match)
				}
			}
		}
	}
	return k8sResources
}
func setComplexResourceMap(frameworks []reporthandling.Framework) map[string]map[string]map[string]interface{} {
	k8sResources := make(map[string]map[string]map[string]interface{})
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				for _, match := range rule.Match {
					insertK8sResources(k8sResources, match)
				}
			}
		}
	}
	return k8sResources
}
func insertK8sResources(k8sResources map[string]map[string]map[string]interface{}, match reporthandling.RuleMatchObjects) {
	for _, apiGroup := range match.APIGroups {
		if v, ok := k8sResources[apiGroup]; !ok || v == nil {
			k8sResources[apiGroup] = make(map[string]map[string]interface{})
		}
		for _, apiVersions := range match.APIVersions {
			if v, ok := k8sResources[apiGroup][apiVersions]; !ok || v == nil {
				k8sResources[apiGroup][apiVersions] = make(map[string]interface{})
			}
			for _, resource := range match.Resources {
				if _, ok := k8sResources[apiGroup][apiVersions][resource]; !ok {
					k8sResources[apiGroup][apiVersions][resource] = nil
				}
			}
		}
	}
}
