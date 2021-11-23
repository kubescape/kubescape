package printer

import (
	"fmt"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
)

// Group workloads by namespace - return {"namespace": <[]WorkloadSummary>}
func groupByNamespaceOrKind(resources []WorkloadSummary, status func(workloadSummary *WorkloadSummary) bool) map[string][]WorkloadSummary {
	mapResources := make(map[string][]WorkloadSummary)
	for i := range resources {
		if status(&resources[i]) {
			if resources[i].Namespace == "" && isKindToBeGrouped(resources[i].Kind) {
				if r, ok := mapResources[resources[i].Kind]; ok {
					r = append(r, resources[i])
					mapResources[resources[i].Kind] = r
				} else {
					mapResources[resources[i].Kind] = []WorkloadSummary{resources[i]}
				}
			} else if r, ok := mapResources[resources[i].Namespace]; ok {
				r = append(r, resources[i])
				mapResources[resources[i].Namespace] = r
			} else {
				mapResources[resources[i].Namespace] = []WorkloadSummary{resources[i]}
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

func listResultSummary(ruleReports []reporthandling.RuleReport) []WorkloadSummary {
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
				resource[i].Exception = ruleReport.Exception
				if ok := track[resource[i].ToString()]; !ok {
					track[resource[i].ToString()] = true
					workloadsSummary = append(workloadsSummary, resource[i])
				}
			}
		}
	}
	return workloadsSummary
}
func ruleResultSummary(obj reporthandling.AlertObject) ([]WorkloadSummary, error) {
	resource := []WorkloadSummary{}

	for i := range obj.K8SApiObjects {
		r, err := newWorkloadSummary(obj.K8SApiObjects[i])
		if err != nil {
			return resource, err
		}

		resource = append(resource, *r)
	}
	if obj.ExternalObjects != nil {
		r, err := newWorkloadSummaryExternalObj(obj.ExternalObjects)
		if err != nil {
			return resource, err
		}
		resource = append(resource, *r)
	}

	return resource, nil
}

func newWorkloadSummary(obj map[string]interface{}) (*WorkloadSummary, error) {
	r := &WorkloadSummary{}

	workload := workloadinterface.NewWorkloadObj(obj)
	if workload == nil {
		return r, fmt.Errorf("expecting k8s API object")
	}
	r.Kind = workload.GetKind()
	r.Namespace = workload.GetNamespace()
	r.Name = workload.GetName()
	return r, nil
}

func newWorkloadSummaryExternalObj(obj map[string]interface{}) (*WorkloadSummary, error) {
	r := &WorkloadSummary{}
	relatedObjectsMap := []map[string]string{}
	relatedObjects := []workloadinterface.IMetadata{}
	if relatedObjectslist, ok := obj["relatedObjects"].([]interface{}); ok {
		for i, related := range relatedObjectslist {
			if r, ok := related.(map[string]interface{}); ok {
				o := workloadinterface.NewWorkloadObj(r)
				if ns := o.GetNamespace(); i == 0 && ns != "" {
					relatedObjectsMap = append(relatedObjectsMap, map[string]string{"Namespace": ns})
				}
				relatedObjectsMap = append(relatedObjectsMap, map[string]string{o.GetKind(): o.GetName()})
				relatedObjects = append(relatedObjects, o)
			}
		}
	}
	vector := workloadinterface.NewRegoResponseVectorObject(obj, relatedObjects)
	if vector == nil {
		return r, fmt.Errorf("error creating rego response vector obj")
	}
	r.Kind = vector.GetKind()
	r.Namespace = vector.GetNamespace()
	r.Name = vector.GetName()
	r.RelatedObjects = relatedObjectsMap
	return r, nil
}
