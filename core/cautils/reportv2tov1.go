package cautils

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func ReportV2ToV1(opaSessionObj *OPASessionObj) *reporthandling.PostureReport {
	report := &reporthandling.PostureReport{}

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
		frameworks = append(frameworks, fwv1)
		fwv1.Score = opaSessionObj.Report.SummaryDetails.Score
	}

	// setup counters and score
	for f := range frameworks {
		// set counters
		reporthandling.SetUniqueResourcesCounter(&frameworks[f])
	}

	report.FrameworkReports = frameworks
	return report
}

func controlReportV2ToV1(opaSessionObj *OPASessionObj, frameworkName string, controls map[string]reportsummary.ControlSummary) []reporthandling.ControlReport {
	controlRepors := []reporthandling.ControlReport{}
	for controlID, crv2 := range controls {
		crv1 := reporthandling.ControlReport{}
		crv1.ControlID = controlID
		crv1.BaseScore = crv2.ScoreFactor
		crv1.Name = crv2.GetName()
		crv1.Score = crv2.GetScore()
		crv1.Control_ID = controlID

		// TODO - add fields
		crv1.Description = crv2.Description
		crv1.Remediation = crv2.Remediation

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
						for i := range rulev2.Paths {
							if rulev2.Paths[i].FailedPath != "" {
								ruleResponse.FailedPaths = append(ruleResponse.FailedPaths, rulev2.Paths[i].FailedPath)
							}
							if rulev2.Paths[i].FixPath.Path != "" {
								ruleResponse.FixPaths = append(ruleResponse.FixPaths, rulev2.Paths[i].FixPath)
							}
						}
						ruleResponse.RuleStatus = string(status.Status())
						if len(rulev2.Exception) > 0 {
							ruleResponse.Exception = &rulev2.Exception[0]
						}

						if fullRessource, ok := opaSessionObj.AllResources[resourceID]; ok {
							tmp := fullRessource.GetObject()
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
		controlRepors = append(controlRepors, crv1)
	}
	return controlRepors
}
