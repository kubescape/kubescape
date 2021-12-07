package printer

import (
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
)

// Group workloads by namespace - return {"namespace": <[]WorkloadSummary>}
func groupByNamespaceOrKind(resources []WorkloadSummary, status func(workloadSummary *WorkloadSummary) bool) map[string][]WorkloadSummary {
	mapResources := make(map[string][]WorkloadSummary)
	for i := range resources {
		if status(&resources[i]) {
			if isKindToBeGrouped(resources[i].resource.GetKind()) {
				if r, ok := mapResources[resources[i].resource.GetKind()]; ok {
					r = append(r, resources[i])
					mapResources[resources[i].resource.GetKind()] = r
				} else {
					mapResources[resources[i].resource.GetKind()] = []WorkloadSummary{resources[i]}
				}
			} else if r, ok := mapResources[resources[i].resource.GetNamespace()]; ok {
				r = append(r, resources[i])
				mapResources[resources[i].resource.GetNamespace()] = r
			} else {
				mapResources[resources[i].resource.GetNamespace()] = []WorkloadSummary{resources[i]}
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

func listResultSummary(ruleReports []reporthandling.RuleReport, allResources map[string]workloadinterface.IMetadata) []WorkloadSummary {
	workloadsSummary := []WorkloadSummary{}

	for c := range ruleReports {
		resourcesIDs := ruleReports[c].ListResourcesIDs()
		workloadsSummary = append(workloadsSummary, newListWorkloadsSummary(allResources, resourcesIDs.GetFailedResources(), reporthandling.StatusFailed)...)
		workloadsSummary = append(workloadsSummary, newListWorkloadsSummary(allResources, resourcesIDs.GetWarningResources(), reporthandling.StatusWarning)...)
		workloadsSummary = append(workloadsSummary, newListWorkloadsSummary(allResources, resourcesIDs.GetPassedResources(), reporthandling.StatusPassed)...)
	}
	return workloadsSummary
}

func newListWorkloadsSummary(allResources map[string]workloadinterface.IMetadata, resourcesIDs []string, status string) []WorkloadSummary {
	workloadsSummary := []WorkloadSummary{}

	for _, i := range resourcesIDs {
		workloadsSummary = append(workloadsSummary, WorkloadSummary{
			resource: allResources[i],
			status:   status,
		})
	}
	return workloadsSummary
}
