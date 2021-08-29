package printer

import (
	"fmt"

	"kubescape/cautils/k8sinterface"
	"kubescape/cautils/opapolicy"
)

// Group workloads by namespace - return {"namespace": <[]WorkloadSummary>}
func groupByNamespace(resources []WorkloadSummary) map[string][]WorkloadSummary {
	mapResources := make(map[string][]WorkloadSummary)
	for i := range resources {
		if r, ok := mapResources[resources[i].Namespace]; ok {
			r = append(r, resources[i])
			mapResources[resources[i].Namespace] = r
		} else {
			mapResources[resources[i].Namespace] = []WorkloadSummary{resources[i]}
		}
	}
	return mapResources
}
func listResultSummary(ruleReports []opapolicy.RuleReport) []WorkloadSummary {
	workloadsSummary := []WorkloadSummary{}
	track := map[string]bool{}

	for c := range ruleReports {
		for _, ruleReport := range ruleReports[c].RuleResponses {
			resource, err := ruleResultSummary(ruleReport.AlertObject)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}

			// add resource only once
			for i := range resource {
				if ok := track[resource[i].ToString()]; !ok {
					track[resource[i].ToString()] = true
					workloadsSummary = append(workloadsSummary, resource[i])
				}
			}
		}
	}
	return workloadsSummary
}
func ruleResultSummary(obj opapolicy.AlertObject) ([]WorkloadSummary, error) {
	resource := []WorkloadSummary{}

	for i := range obj.K8SApiObjects {
		r, err := newWorkloadSummary(obj.K8SApiObjects[i])
		if err != nil {
			return resource, err
		}
		resource = append(resource, *r)
	}

	return resource, nil
}

func newWorkloadSummary(obj map[string]interface{}) (*WorkloadSummary, error) {
	r := &WorkloadSummary{}

	workload := k8sinterface.NewWorkloadObj(obj)
	if workload == nil {
		return r, fmt.Errorf("expecting k8s API object")
	}
	r.Kind = workload.GetKind()
	r.Namespace = workload.GetNamespace()
	r.Name = workload.GetName()
	return r, nil
}
