package opaprocessor

import (
	pkgcautils "github.com/armosec/utils-go/utils"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/exceptions"
	"github.com/armosec/opa-utils/reporthandling"
	resources "github.com/armosec/opa-utils/resources"

	"github.com/golang/glog"
)

func (opap *OPAProcessor) updateResults() {
	// remove data from all objects
	for i := range opap.AllResources {
		removeData(opap.AllResources[i])
	}

	for f := range opap.PostureReport.FrameworkReports {
		// set exceptions
		exceptions.SetFrameworkExceptions(&opap.PostureReport.FrameworkReports[f], opap.Exceptions, cautils.ClusterName)

		// set counters
		reporthandling.SetUniqueResourcesCounter(&opap.PostureReport.FrameworkReports[f])

		// set default score
		// reporthandling.SetDefaultScore(&opap.PostureReport.FrameworkReports[f])
	}
}

func getKubernetesObjects(k8sResources *cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, match []reporthandling.RuleMatchObjects) []workloadinterface.IMetadata {
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
							for i := range k8sObj {
								k8sObjects = append(k8sObjects, allResources[k8sObj[i]])
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

func ruleWithArmoOpaDependency(annotations map[string]interface{}) bool {
	if annotations == nil {
		return false
	}
	if s, ok := annotations["armoOpa"]; ok { // TODO - make global
		return pkgcautils.StringToBool(s.(string))
	}
	return false
}

// Checks that kubescape version is in range of use for this rule
// In local build (BuildNumber = ""):
// returns true only if rule doesn't have the "until" attribute
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
		removeSecretData(workload)
	case "ConfigMap":
		removeConfigMapData(workload)
	default:
		removePodData(workload)
	}
}

func removeConfigMapData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")
	overrideSensitiveData(workload)
}

func overrideSensitiveData(workload workloadinterface.IWorkload) {
	dataInterface, ok := workloadinterface.InspectMap(workload.GetObject(), "data")
	if ok {
		data, ok := dataInterface.(map[string]interface{})
		if ok {
			for key := range data {
				workloadinterface.SetInMap(workload.GetObject(), []string{"data"}, key, "XXXXXX")
			}
		}
	}
}

func removeSecretData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")
	overrideSensitiveData(workload)
}
func removePodData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")

	containers, err := workload.GetContainers()
	if err != nil || len(containers) == 0 {
		return
	}
	for i := range containers {
		for j := range containers[i].Env {
			containers[i].Env[j].Value = "XXXXXX"
		}
	}
	workloadinterface.SetInMap(workload.GetObject(), workloadinterface.PodSpec(workload.GetKind()), "containers", containers)
}

func ruleData(rule *reporthandling.PolicyRule) string {
	return rule.Rule
}

func ruleEnumeratorData(rule *reporthandling.PolicyRule) string {
	return rule.ResourceEnumerator
}
