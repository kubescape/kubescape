package printer

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadSummary struct {
	resource workloadinterface.IMetadata
	status   apis.ScanningStatus
}

func workloadSummaryFailed(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusFailed
}

func workloadSummaryPassed(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusPassed
}

func workloadSummarySkipped(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusSkipped
}

// Group workloads by namespace - return {"namespace": <[]WorkloadSummary>}
func groupByNamespaceOrKind(resources []WorkloadSummary, status func(workloadSummary *WorkloadSummary) bool) map[string][]WorkloadSummary {
	mapResources := make(map[string][]WorkloadSummary)
	for i := range resources {
		if !status(&resources[i]) {
			continue
		}
		t := resources[i].resource.GetObjectType()
		if t == objectsenvelopes.TypeRegoResponseVectorObject && !isKindToBeGrouped(resources[i].resource.GetKind()) {
			t = workloadinterface.TypeWorkloadObject
		}
		switch t { // TODO - find a better way to defind the groups
		case workloadinterface.TypeWorkloadObject:
			ns := ""
			if resources[i].resource.GetNamespace() != "" {
				ns = "Namespace " + resources[i].resource.GetNamespace()
			}
			if r, ok := mapResources[ns]; ok {
				r = append(r, resources[i])
				mapResources[ns] = r
			} else {
				mapResources[ns] = []WorkloadSummary{resources[i]}
			}
		case objectsenvelopes.TypeRegoResponseVectorObject:
			group := resources[i].resource.GetKind() + "s"
			if r, ok := mapResources[group]; ok {
				r = append(r, resources[i])
				mapResources[group] = r
			} else {
				mapResources[group] = []WorkloadSummary{resources[i]}
			}
		default:
			group, _ := k8sinterface.SplitApiVersion(resources[i].resource.GetApiVersion())
			if r, ok := mapResources[group]; ok {
				r = append(r, resources[i])
				mapResources[group] = r
			} else {
				mapResources[group] = []WorkloadSummary{resources[i]}
			}
		}
	}
	return mapResources
}

func isKindToBeGrouped(kind string) bool {
	if kind == "Group" || kind == "User" {
		return true
	}
	return false
}

func listResultSummary(controlSummary reportsummary.IControlSummary, allResources map[string]workloadinterface.IMetadata) []WorkloadSummary {
	resourceIds := helpersv1.GetAllListsFromPool()
	defer helpersv1.PutAllListsToPool(resourceIds)

	resourceIds = controlSummary.ListResourcesIDs(resourceIds)
	workloadsSummary := make([]WorkloadSummary, 0, resourceIds.Len())
	for rId, status := range resourceIds.All() {
		if status == apis.StatusUnknown {
			continue
		}

		if r, ok := allResources[rId]; ok {
			workloadsSummary = append(workloadsSummary, WorkloadSummary{
				resource: r,
				status:   status,
			})
		}
	}

	return workloadsSummary
}
