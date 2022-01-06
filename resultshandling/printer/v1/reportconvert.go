package v1

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	helpersv1 "github.com/armosec/opa-utils/reporthandling/helpers/v1"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/armosec/opa-utils/score"
)

func reportV2ToV1(opaSessionObj *cautils.OPASessionObj) {

	opaSessionObj.PostureReport.ClusterCloudProvider = opaSessionObj.Report.ClusterCloudProvider

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
		fwv1.Score = 0

		fwv1.ControlReports = append(fwv1.ControlReports, controlReportV2ToV1(opaSessionObj, "", opaSessionObj.Report.SummaryDetails.Controls)...)
		frameworks = append(frameworks, fwv1)
	}

	// remove unused data
	opaSessionObj.Report = nil
	opaSessionObj.ResourcesResult = nil

	// setup counters and score
	for f := range frameworks {
		// // set exceptions
		// exceptions.SetFrameworkExceptions(frameworks, opap.Exceptions, cautils.ClusterName)

		// set counters
		reporthandling.SetUniqueResourcesCounter(&frameworks[f])

		// set default score
		reporthandling.SetDefaultScore(&frameworks[f])
	}

	// update score
	scoreutil := score.NewScore(opaSessionObj.AllResources)
	scoreutil.Calculate(frameworks)

	opaSessionObj.PostureReport.FrameworkReports = frameworks

	// for i := range frameworks {
	// 	for j := range frameworks[i].ControlReports {
	// 		// frameworks[i].ControlReports[j].Score
	// 		for w := range opaSessionObj.Report.SummaryDetails.Frameworks {
	// 			if opaSessionObj.Report.SummaryDetails.Frameworks[w].Name == frameworks[i].Name {
	// 				opaSessionObj.Report.SummaryDetails.Frameworks[w].Score = frameworks[i].Score
	// 			}
	// 			if c, ok := opaSessionObj.Report.SummaryDetails.Frameworks[w].Controls[frameworks[i].ControlReports[j].ControlID]; ok {
	// 				c.Score = frameworks[i].ControlReports[j].Score
	// 				opaSessionObj.Report.SummaryDetails.Frameworks[w].Controls[frameworks[i].ControlReports[j].ControlID] = c
	// 			}
	// 		}
	// 		if c, ok := opaSessionObj.Report.SummaryDetails.Controls[frameworks[i].ControlReports[j].ControlID]; ok {
	// 			c.Score = frameworks[i].ControlReports[j].Score
	// 			opaSessionObj.Report.SummaryDetails.Controls[frameworks[i].ControlReports[j].ControlID] = c
	// 		}
	// 	}
	// }
}

func controlReportV2ToV1(opaSessionObj *cautils.OPASessionObj, frameworkName string, controls map[string]reportsummary.ControlSummary) []reporthandling.ControlReport {
	controlRepors := []reporthandling.ControlReport{}
	for controlID, crv2 := range controls {
		crv1 := reporthandling.ControlReport{}
		crv1.ControlID = controlID
		crv1.BaseScore = crv2.ScoreFactor
		crv1.Name = crv2.GetName()

		crv1.Score = crv2.GetScore()

		// TODO - add fields
		crv1.Description = crv2.Description
		crv1.Remediation = crv2.Remediation

		rulesv1 := initializeRuleList(&crv2, opaSessionObj.ResourcesResult)

		for _, resourceID := range crv2.List().All() {
			if result, ok := opaSessionObj.ResourcesResult[resourceID]; ok {
				for _, rulev2 := range result.ListRulesOfControl(crv2.GetID(), "") {

					rulev1 := rulesv1[rulev2.GetName()]
					status := rulev2.GetStatus(&helpersv1.Filters{FrameworkNames: []string{frameworkName}})

					if status.IsFailed() || status.IsExcluded() {

						// rule response
						ruleResponse := reporthandling.RuleResponse{}
						ruleResponse.Rulename = rulev2.GetName()
						for i := range rulev2.Paths {
							ruleResponse.FailedPaths = append(ruleResponse.FailedPaths, rulev2.Paths[i].FailedPath)
						}
						ruleResponse.RuleStatus = string(status.Status())
						if len(rulev2.Exception) > 0 {
							ruleResponse.Exception = &rulev2.Exception[0]
						}

						if fullRessource, ok := opaSessionObj.AllResources[resourceID]; ok {
							ruleResponse.AlertObject.K8SApiObjects = append(ruleResponse.AlertObject.K8SApiObjects, fullRessource.GetObject())
						}
						rulev1.RuleResponses = append(rulev1.RuleResponses, ruleResponse)

					}

					rulev1.ListInputKinds = append(rulev1.ListInputKinds, resourceID)
					rulesv1[rulev2.GetName()] = rulev1
				}
			}
		}
		if len(rulesv1) > 0 {
			for i := range rulesv1 {
				crv1.RuleReports = append(crv1.RuleReports, rulesv1[i])
			}
		}
		controlRepors = append(controlRepors, crv1)
	}
	return controlRepors
}

func initializeRuleList(crv2 *reportsummary.ControlSummary, resourcesResult map[string]resourcesresults.Result) map[string]reporthandling.RuleReport {
	rulesv1 := map[string]reporthandling.RuleReport{} // ruleName: rules

	for _, resourceID := range crv2.List().All() {
		if result, ok := resourcesResult[resourceID]; ok {
			for _, rulev2 := range result.ListRulesOfControl(crv2.GetID(), "") {
				// add to rule
				if _, ok := rulesv1[rulev2.GetName()]; !ok {
					rulesv1[rulev2.GetName()] = reporthandling.RuleReport{
						Name: rulev2.GetName(),
					}
				}
			}
		}
	}
	return rulesv1
}
