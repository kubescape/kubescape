package printer

import (
	"fmt"

	"kube-escape/cautils/k8sinterface"
	"kube-escape/cautils/opapolicy"
)

// Group workloads by namespace - return {"namespace": <[]WorkloadSummery>}
func groupByNamespace(resources []WorkloadSummery) map[string][]WorkloadSummery {
	mapResources := make(map[string][]WorkloadSummery)
	for i := range resources {
		if r, ok := mapResources[resources[i].Namespace]; ok {
			r = append(r, resources[i])
			mapResources[resources[i].Namespace] = r
		} else {
			mapResources[resources[i].Namespace] = []WorkloadSummery{resources[i]}
		}
	}
	return mapResources
}
func listResultSummery(ruleReports []opapolicy.RuleReport) []WorkloadSummery {
	workloadsSummery := []WorkloadSummery{}
	track := map[string]bool{}

	for c := range ruleReports {
		for _, ruleReport := range ruleReports[c].RuleResponses {
			resource, err := ruleResultSummery(ruleReport.AlertObject)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}

			// add resource only once
			for i := range resource {
				if ok := track[resource[i].ToString()]; !ok {
					track[resource[i].ToString()] = true
					workloadsSummery = append(workloadsSummery, resource[i])
				}
			}
		}
	}
	return workloadsSummery
}
func ruleResultSummery(obj opapolicy.AlertObject) ([]WorkloadSummery, error) {
	resource := []WorkloadSummery{}

	for i := range obj.K8SApiObjects {
		r, err := newWorkloadSummery(obj.K8SApiObjects[i])
		if err != nil {
			return resource, err
		}
		resource = append(resource, *r)
	}

	return resource, nil
}

func newWorkloadSummery(obj map[string]interface{}) (*WorkloadSummery, error) {
	r := &WorkloadSummery{}

	workload := k8sinterface.NewWorkloadObj(obj)
	if workload == nil {
		return r, fmt.Errorf("expecting k8s API object")
	}
	r.Kind = workload.GetKind()
	r.Namespace = workload.GetNamespace()
	r.Name = workload.GetName()
	return r, nil
}
