package v2

import (
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
)

// finalizeV2Report finalize the results objects by copying data from map to lists
func finalizeJson(opaSessionObj *cautils.OPASessionObj) {
	if len(opaSessionObj.Report.Results) == 0 {
		opaSessionObj.Report.Results = make([]resourcesresults.Result, len(opaSessionObj.ResourcesResult))
		finalizeResults(opaSessionObj.Report.Results, opaSessionObj.ResourcesResult)
	}

	if len(opaSessionObj.Report.Resources) == 0 {
		opaSessionObj.Report.Resources = make([]reporthandling.Resource, len(opaSessionObj.AllResources))
		finalizeResources(opaSessionObj.Report.Resources, opaSessionObj.Report.Results, opaSessionObj.AllResources)
	}

}
func finalizeResults(results []resourcesresults.Result, resourcesResult map[string]resourcesresults.Result) {
	index := 0
	for resourceID := range resourcesResult {
		results[index] = resourcesResult[resourceID]
		index++
	}
}

func finalizeResources(resources []reporthandling.Resource, results []resourcesresults.Result, allResources map[string]workloadinterface.IMetadata) {
	index := 0
	for i := range results {
		if obj, ok := allResources[results[i].ResourceID]; ok {
			r := *reporthandling.NewResource(obj.GetObject())
			r.ResourceID = results[i].ResourceID
			resources[index] = r
		}

		index++
	}
}

func logOUtputFile(fileName string) {
	if fileName != "/dev/stdout" && fileName != "/dev/stderr" {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}

}
