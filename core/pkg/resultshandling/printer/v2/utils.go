package v2

import (
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
)

// finalizeV2Report finalize the results objects by copying data from map to lists
func DataToJson(data *cautils.OPASessionObj) *reporthandlingv2.PostureReport {
	report := reporthandlingv2.PostureReport{
		SummaryDetails:       data.Report.SummaryDetails,
		ClusterAPIServerInfo: data.Report.ClusterAPIServerInfo,
		ReportGenerationTime: data.Report.ReportGenerationTime,
		Attributes:           data.Report.Attributes,
		ClusterName:          data.Report.ClusterName,
		CustomerGUID:         data.Report.CustomerGUID,
		ClusterCloudProvider: data.Report.ClusterCloudProvider,
	}

	report.Results = make([]resourcesresults.Result, len(data.ResourcesResult))
	finalizeResults(report.Results, data.ResourcesResult)

	report.Resources = make([]reporthandling.Resource, 0) // do not initialize slice length
	finalizeResources(report.Resources, report.Results, data.AllResources)

	return &report
}
func finalizeResults(results []resourcesresults.Result, resourcesResult map[string]resourcesresults.Result) {
	index := 0
	for resourceID := range resourcesResult {
		results[index] = resourcesResult[resourceID]
		index++
	}
}

func finalizeResources(resources []reporthandling.Resource, results []resourcesresults.Result, allResources map[string]workloadinterface.IMetadata) {
	for i := range results {
		if obj, ok := allResources[results[i].ResourceID]; ok {
			r := *reporthandling.NewResource(obj.GetObject())
			r.ResourceID = results[i].ResourceID
			resources = append(resources, r)
		}
	}
}

func logOUtputFile(fileName string) {
	if fileName != "/dev/stdout" && fileName != "/dev/stderr" {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}

}
