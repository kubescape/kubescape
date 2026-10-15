package cautils

import (
	"maps"
	"slices"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func ReportV2ToV1(opaSessionObj *OPASessionObj) *reporthandling.PostureReport {
	report := &reporthandling.PostureReport{}

	if opaSessionObj == nil || opaSessionObj.Report == nil {
		return report
	}

	report.CustomerGUID = opaSessionObj.Report.CustomerGUID
	report.ClusterName = opaSessionObj.Report.ClusterName
	report.ClusterAPIServerInfo = opaSessionObj.Report.ClusterAPIServerInfo
	report.ClusterCloudProvider = opaSessionObj.Report.ClusterCloudProvider
	report.ReportID = opaSessionObj.Report.ReportID
	report.JobID = opaSessionObj.Report.JobID
	report.ReportGenerationTime = opaSessionObj.Report.ReportGenerationTime
	report.Resources = opaSessionObj.Report.Resources

	frameworks := []reporthandling.FrameworkReport{}

	if len(opaSessionObj.Report.SummaryDetails.Frameworks) > 0 {
		for _, fwv2 := range opaSessionObj.Report.SummaryDetails.Frameworks {
			fwv1 := reporthandling.FrameworkReport{}
			fwv1.Name = fwv2.GetName()
			fwv1.Score = fwv2.GetScore()
			fwv1.ControlReports = append(fwv1.ControlReports, controlReportV2ToV1(opaSessionObj, fwv2.GetName(), fwv2.Controls)...)
			frameworks = append(frameworks, fwv1)

		}
	} else {
		fwv1 := reporthandling.FrameworkReport{}
		fwv1.Name = ""

		fwv1.ControlReports = append(fwv1.ControlReports, controlReportV2ToV1(opaSessionObj, "", opaSessionObj.Report.SummaryDetails.Controls)...)
		fwv1.Score = opaSessionObj.Report.SummaryDetails.Score
		frameworks = append(frameworks, fwv1)
	}

	// setup counters and score
	for f := range frameworks {
		// set counters
		reporthandling.SetUniqueResourcesCounter(&frameworks[f])

		// apply the summary-derived control counters after the helper recomputation
		var controls map[string]reportsummary.ControlSummary
		var statusCounters reportsummary.StatusCounters
		if len(opaSessionObj.Report.SummaryDetails.Frameworks) > 0 {
			controls = opaSessionObj.Report.SummaryDetails.Frameworks[f].Controls
			statusCounters = opaSessionObj.Report.SummaryDetails.Frameworks[f].StatusCounters
		} else {
			controls = opaSessionObj.Report.SummaryDetails.Controls
			statusCounters = opaSessionObj.Report.SummaryDetails.StatusCounters
		}

		for c := range frameworks[f].ControlReports {
			if crv2, ok := controls[frameworks[f].ControlReports[c].ControlID]; ok {
				frameworks[f].ControlReports[c].TotalResources = crv2.StatusCounters.PassedResources + crv2.StatusCounters.FailedResources + crv2.StatusCounters.SkippedResources + crv2.StatusCounters.ExcludedResources
				frameworks[f].ControlReports[c].FailedResources = crv2.StatusCounters.FailedResources
				frameworks[f].ControlReports[c].WarningResources = crv2.StatusCounters.SkippedResources + crv2.StatusCounters.ExcludedResources
			}
		}

		if statusCounters.PassedResources+statusCounters.FailedResources+statusCounters.SkippedResources+statusCounters.ExcludedResources > 0 {
			frameworks[f].TotalResources = statusCounters.PassedResources + statusCounters.FailedResources + statusCounters.SkippedResources + statusCounters.ExcludedResources
			frameworks[f].FailedResources = statusCounters.FailedResources
			frameworks[f].WarningResources = statusCounters.SkippedResources + statusCounters.ExcludedResources
		} else if len(frameworks[f].ControlReports) == 1 {
			frameworks[f].TotalResources = frameworks[f].ControlReports[0].TotalResources
			frameworks[f].FailedResources = frameworks[f].ControlReports[0].FailedResources
			frameworks[f].WarningResources = frameworks[f].ControlReports[0].WarningResources
		}
	}

	report.FrameworkReports = frameworks
	return report
}

func controlReportV2ToV1(opaSessionObj *OPASessionObj, frameworkName string, controls map[string]reportsummary.ControlSummary) []reporthandling.ControlReport {
	controlReports := []reporthandling.ControlReport{}
	for controlID, crv2 := range controls {
		crv1 := reporthandling.ControlReport{}
		crv1.ControlID = controlID
		crv1.BaseScore = crv2.ScoreFactor
		crv1.Name = crv2.GetName()
		crv1.Score = crv2.GetScore()
		crv1.Control_ID = controlID

		crv1.Description = crv2.GetDescription()
		crv1.Remediation = crv2.GetRemediation()

		crv1.TotalResources = crv2.StatusCounters.PassedResources + crv2.StatusCounters.FailedResources + crv2.StatusCounters.SkippedResources + crv2.StatusCounters.ExcludedResources
		crv1.FailedResources = crv2.StatusCounters.FailedResources
		crv1.WarningResources = crv2.StatusCounters.SkippedResources + crv2.StatusCounters.ExcludedResources
		rulesv1 := map[string]reporthandling.RuleReport{}
		l := helpersv1.GetAllListsFromPool()
		for resourceID := range crv2.ListResourcesIDs(l).All() {
			if result, ok := opaSessionObj.ResourcesResult[resourceID]; ok {
				for _, rulev2 := range result.ListRulesOfControl(crv2.GetID(), "") {

					if _, ok := rulesv1[rulev2.GetName()]; !ok {
						rulesv1[rulev2.GetName()] = reporthandling.RuleReport{
							Name: rulev2.GetName(),
							RuleStatus: reporthandling.RuleStatus{
								Status: "success",
							},
						}
					}

					rulev1 := rulesv1[rulev2.GetName()]
					status := rulev2.GetStatus(nil)

					if status.IsFailed() {

						// rule response
						ruleResponse := reporthandling.RuleResponse{}
						ruleResponse.Rulename = rulev2.GetName()
						// The processor records a rule's paths as DeletePath,
						// ReviewPath, FixPath and FixCommand entries, each tagged
						// with the resource it belongs to; FailedPath is only set
						// by older data. Entries for a related resource (a Pod's
						// exposing Service, say) go to that resource's
						// RelatedObject, not to this resource's response.
						ruleResponse.AssistedRemediation, ruleResponse.RelatedObjects = splitRemediationByResource(opaSessionObj, resourceID, rulev2.Paths)
						ruleResponse.RuleStatus = string(status.Status())
						if len(rulev2.Exception) > 0 {
							ruleResponse.Exception = &rulev2.Exception[0]
						}

						if fullResource, ok := opaSessionObj.GetResource(resourceID); ok {
							tmp := maps.Clone(fullResource.GetObject())
							workloadinterface.RemoveFromMap(tmp, "spec")
							ruleResponse.AlertObject.K8SApiObjects = append(ruleResponse.AlertObject.K8SApiObjects, tmp)
						}
						rulev1.RuleResponses = append(rulev1.RuleResponses, ruleResponse)
					}

					rulev1.ListInputKinds = append(rulev1.ListInputKinds, resourceID)
					rulesv1[rulev2.GetName()] = rulev1
				}
			}
		}
		helpersv1.PutAllListsToPool(l)
		if len(rulesv1) > 0 {
			for i := range rulesv1 {
				crv1.RuleReports = append(crv1.RuleReports, rulesv1[i])
			}
		}
		if len(crv1.RuleReports) == 0 {
			crv1.RuleReports = []reporthandling.RuleReport{}
		}
		controlReports = append(controlReports, crv1)
	}
	return controlReports
}

// splitRemediationByResource converts a v2 rule's paths into the v1
// assisted-remediation fields. Paths whose ResourceID is resourceID, or that
// carry no ResourceID (older data), describe the failed resource itself and
// are returned as its remediation. Paths tagged with another resource's ID
// describe a related object - the processor records a RelatedObject's paths
// under that object's ID - and are returned as one v1 RelatedObject per
// resource, in the order they first appear, so a consumer does not apply a
// related object's remediation to the failed resource. A related resource
// that is not in the session is dropped rather than reattributed. Fix
// commands are de-duplicated per resource and joined with newlines.
func splitRemediationByResource(opaSessionObj *OPASessionObj, resourceID string, paths []armotypes.PosturePaths) (reporthandling.AssistedRemediation, []reporthandling.RelatedObject) {
	type target struct {
		remediation reporthandling.AssistedRemediation
		commands    []string
	}
	targets := map[string]*target{}
	var order []string
	for i := range paths {
		id := paths[i].ResourceID
		if id == "" {
			id = resourceID
		}
		t, ok := targets[id]
		if !ok {
			t = &target{}
			targets[id] = t
			order = append(order, id)
		}
		if paths[i].FailedPath != "" {
			t.remediation.FailedPaths = append(t.remediation.FailedPaths, paths[i].FailedPath)
		}
		if paths[i].DeletePath != "" {
			t.remediation.DeletePaths = append(t.remediation.DeletePaths, paths[i].DeletePath)
		}
		if paths[i].ReviewPath != "" {
			t.remediation.ReviewPaths = append(t.remediation.ReviewPaths, paths[i].ReviewPath)
		}
		if paths[i].FixPath.Path != "" {
			t.remediation.FixPaths = append(t.remediation.FixPaths, paths[i].FixPath)
		}
		if cmd := paths[i].FixCommand; cmd != "" && !slices.Contains(t.commands, cmd) {
			t.commands = append(t.commands, cmd)
		}
	}

	var primary reporthandling.AssistedRemediation
	var related []reporthandling.RelatedObject
	for _, id := range order {
		t := targets[id]
		t.remediation.FixCommand = strings.Join(t.commands, "\n")
		if id == resourceID {
			primary = t.remediation
			continue
		}
		resource, ok := opaSessionObj.GetResource(id)
		if !ok {
			continue
		}
		obj := maps.Clone(resource.GetObject())
		workloadinterface.RemoveFromMap(obj, "spec")
		related = append(related, reporthandling.RelatedObject{Object: obj, AssistedRemediation: t.remediation})
	}
	return primary, related
}
