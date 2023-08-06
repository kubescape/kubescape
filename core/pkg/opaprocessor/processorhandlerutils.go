package opaprocessor

import (
	"context"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	resources "github.com/kubescape/opa-utils/resources"
	"go.opentelemetry.io/otel"
	"golang.org/x/exp/slices"
)

const clusterScope = "clusterScope"

// updateResults updates the results objects and report objects. This is a critical function - DO NOT CHANGE
//
// The function:
//   - removes sensible data
//   - adds exceptions (and updates controls status)
//   - summarizes results
func (opap *OPAProcessor) updateResults(ctx context.Context) {
	_, span := otel.Tracer("").Start(ctx, "OPAProcessor.updateResults")
	defer span.End()

	// remove data from all objects
	for i := range opap.AllResources {
		removeData(opap.AllResources[i])
	}

	processor := exceptions.NewProcessor()

	// set exceptions
	for i := range opap.ResourcesResult {
		t := opap.ResourcesResult[i]

		// first set exceptions (reuse the same exceptions processor)
		if resource, ok := opap.AllResources[i]; ok {
			t.SetExceptions(
				resource,
				opap.Exceptions,
				cautils.ClusterName,
				opap.AllPolicies.Controls, // update status depending on action required
				resourcesresults.WithExceptionsProcessor(processor),
			)
		}

		// summarize the resources
		opap.Report.AppendResourceResultToSummary(&t)

		// Add score
		// TODO

		// save changes
		opap.ResourcesResult[i] = t
	}

	// set result summary
	// map control to error
	controlToInfoMap := mapControlToInfo(opap.ResourceToControlsMap, opap.InfoMap, opap.Report.SummaryDetails.Controls)
	opap.Report.SummaryDetails.InitResourcesSummary(controlToInfoMap)
}

func mapControlToInfo(mapResourceToControls map[string][]string, infoMap map[string]apis.StatusInfo, controlSummary reportsummary.ControlSummaries) map[string]apis.StatusInfo {
	controlToInfoMap := make(map[string]apis.StatusInfo)
	for resource, statusInfo := range infoMap {
		controlIDs := mapResourceToControls[resource]
		for _, controlID := range controlIDs {
			ctrl := controlSummary.GetControl(reportsummary.EControlCriteriaID, controlID)
			if ctrl != nil {
				resources := ctrl.NumberOfResources()
				// Check that there are no K8s resources too
				if isEmptyResources(resources) {
					controlToInfoMap[controlID] = statusInfo
				}
			}

		}
	}
	return controlToInfoMap
}

func isEmptyResources(counters reportsummary.ICounters) bool {
	return counters.Failed() == 0 && counters.Skipped() == 0 && counters.Passed() == 0
}

func getAllSupportedObjects(k8sResources cautils.K8SResources, externalResources cautils.ExternalResources, allResources map[string]workloadinterface.IMetadata, rule *reporthandling.PolicyRule) map[string][]workloadinterface.IMetadata {
	// k8sObjects := map[string][]workloadinterface.IMetadata{}
	k8sObjects := getKubernetesObjects(k8sResources, allResources, rule.Match)
	externalObjs := getKubenetesObjectsFromExternalResources(externalResources, allResources, rule.DynamicMatch)
	if len(externalObjs) > 0 {
		l, ok := k8sObjects[clusterScope]
		if !ok {
			l = []workloadinterface.IMetadata{}
		}
		l = append(l, externalObjs...)
		k8sObjects[clusterScope] = l
	}
	return k8sObjects
}

func getKubenetesObjectsFromExternalResources(externalResources cautils.ExternalResources, allResources map[string]workloadinterface.IMetadata, match []reporthandling.RuleMatchObjects) []workloadinterface.IMetadata {
	k8sObjects := []workloadinterface.IMetadata{}

	for m := range match {
		for _, groups := range match[m].APIGroups {
			for _, version := range match[m].APIVersions {
				for _, resource := range match[m].Resources {
					groupResources := k8sinterface.ResourceGroupToString(groups, version, resource)
					for _, groupResource := range groupResources {
						if k8sObj, ok := externalResources[groupResource]; ok {
							for i := range k8sObj {
								if isChildResource(allResources[k8sObj[i]], match) {
									continue
								}
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

func getKubernetesObjects(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, match []reporthandling.RuleMatchObjects) map[string][]workloadinterface.IMetadata {
	k8sObjects := map[string][]workloadinterface.IMetadata{}

	for m := range match {
		for _, groups := range match[m].APIGroups {
			for _, version := range match[m].APIVersions {
				for _, resource := range match[m].Resources {
					groupResources := k8sinterface.ResourceGroupToString(groups, version, resource)
					for _, groupResource := range groupResources {
						if k8sObj, ok := k8sResources[groupResource]; ok {
							for i := range k8sObj {
								obj := allResources[k8sObj[i]]
								if isChildResource(obj, match) {
									continue
								}

								ns := clusterScope
								// if the resource is in namespace scope, get the namespace
								if k8sinterface.IsResourceInNamespaceScope(resource) {
									ns = allResources[k8sObj[i]].GetNamespace()
								}
								if obj.GetKind() == "Namespace" {
									ns = allResources[k8sObj[i]].GetName()
								}
								l, ok := k8sObjects[ns]
								if !ok {
									l = []workloadinterface.IMetadata{}
								}
								l = append(l, allResources[k8sObj[i]])
								k8sObjects[ns] = l
							}
						}
					}
				}
			}
		}
	}

	return k8sObjects
	// return filterOutChildResources(k8sObjects, match)
}

// filterOutChildResources filter out child resources if the parent resource is in the list
func isChildResource(obj workloadinterface.IMetadata, match []reporthandling.RuleMatchObjects) bool {

	if !k8sinterface.IsTypeWorkload(obj.GetObject()) {
		return false
	}
	w := workloadinterface.NewWorkloadObj(obj.GetObject())
	ownerReferences, err := w.GetOwnerReferences()
	if err != nil || len(ownerReferences) == 0 {
		return false
	}
	// if ownerReferences[0].Kind == "Node" {
	// 	return false
	// }
	owners := []string{}
	for m := range match {
		owners = append(owners, match[m].Resources...)
	}

	return slices.Contains(owners, ownerReferences[0].Kind)
}

func getRuleDependencies(ctx context.Context) (map[string]string, error) {
	modules := resources.LoadRegoModules()
	if len(modules) == 0 {
		logger.L().Ctx(ctx).Warning("failed to load rule dependencies")
	}
	return modules, nil
}

func removeData(obj workloadinterface.IMetadata) {
	if !k8sinterface.IsTypeWorkload(obj.GetObject()) {
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
	workloadinterface.RemoveFromMap(workload.GetObject(), "status")

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
