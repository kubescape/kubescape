package resultshandling

import (
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
	v1 "github.com/armosec/opa-utils/reporthandling/helpers/v1"
	"github.com/armosec/opa-utils/score"
)

type ResultsHandler struct {
	opaSessionObj *chan *cautils.OPASessionObj
	reporterObj   reporter.IReport
	printerObj    printer.IPrinter
}

func NewResultsHandler(opaSessionObj *chan *cautils.OPASessionObj, reporterObj reporter.IReport, printerObj printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		opaSessionObj: opaSessionObj,
		reporterObj:   reporterObj,
		printerObj:    printerObj,
	}
}

func (resultsHandler *ResultsHandler) HandleResults(scanInfo *cautils.ScanInfo) float32 {

	opaSessionObj := <-*resultsHandler.opaSessionObj

	resultsHandler.reportV2ToV1(opaSessionObj)

	resultsHandler.printerObj.ActionPrint(opaSessionObj)

	if err := resultsHandler.reporterObj.ActionSendReport(opaSessionObj); err != nil {
		fmt.Println(err)
	}

	// TODO - get score from table
	var score float32 = 0
	for i := range opaSessionObj.PostureReport.FrameworkReports {
		score += opaSessionObj.PostureReport.FrameworkReports[i].Score
	}
	score /= float32(len(opaSessionObj.PostureReport.FrameworkReports))
	resultsHandler.printerObj.Score(score)

	return score
}

// CalculatePostureScore calculate final score
func CalculatePostureScore(postureReport *reporthandling.PostureReport) float32 {
	failedResources := []string{}
	allResources := []string{}
	for _, frameworkReport := range postureReport.FrameworkReports {
		failedResources = reporthandling.GetUniqueResourcesIDs(append(failedResources, frameworkReport.ListResourcesIDs().GetFailedResources()...))
		allResources = reporthandling.GetUniqueResourcesIDs(append(allResources, frameworkReport.ListResourcesIDs().GetAllResources()...))
	}

	return (float32(len(allResources)) - float32(len(failedResources))) / float32(len(allResources))
}

func (resultsHandler *ResultsHandler) reportV2ToV1(opaSessionObj *cautils.OPASessionObj) {
	opaSessionObj.PostureReport.ReportID = opaSessionObj.Report.ReportID
	opaSessionObj.PostureReport.CustomerGUID = opaSessionObj.Report.CustomerGUID
	opaSessionObj.PostureReport.ClusterCloudProvider = opaSessionObj.Report.ClusterCloudProvider
	opaSessionObj.PostureReport.ClusterName = opaSessionObj.Report.ClusterName

	frameworks := []reporthandling.FrameworkReport{}
	fwv1 := reporthandling.FrameworkReport{}
	for _, fwv2 := range opaSessionObj.Report.SummaryDetails.Frameworks {
		fwv1.Name = fwv2.GetName()
		fwv1.Score = fwv2.GetScore()
		fwv1.WarningResources = fwv2.NumberOf().Excluded()
		fwv1.FailedResources = fwv2.NumberOf().Failed()
		fwv1.TotalResources = fwv2.NumberOf().All()

		crv1 := reporthandling.ControlReport{}
		for _, crv2 := range fwv2.Controls {
			crv1.ControlID = crv2.GetID()
			crv1.Name = crv2.GetName()
			crv1.Score = crv2.GetScore()
			crv1.WarningResources = crv2.NumberOf().Excluded()
			crv1.FailedResources = crv2.NumberOf().Failed()
			crv1.TotalResources = crv2.NumberOf().All()

			// TODO - add fields
			// crv1.Description
			// crv1.GUID
			// crv1.Remediation

			rulesv1 := map[string]reporthandling.RuleReport{} // ruleName: rules
			for _, resourceID := range crv2.List().All() {
				if resource, ok := opaSessionObj.ResourcesResult[resourceID]; ok {
					for _, rulev2 := range resource.ListRules() {
						if _, ok := rulesv1[rulev2.GetName()]; !ok {
							rulesv1[rulev2.GetName()] = reporthandling.RuleReport{}
						}
						rulev1 := reporthandling.RuleReport{}
						rulev1.Name = rulev2.GetName()
						// rulev1.Remediation
						rulev1.ResourceUniqueCounter.TotalResources++
						if rulev2.GetStatus(&v1.Filters{FrameworkNames: []string{fwv2.GetName()}}).IsFailed() {
							rulev1.ResourceUniqueCounter.FailedResources++
						} else if rulev2.GetStatus(&v1.Filters{FrameworkNames: []string{fwv2.GetName()}}).IsExcluded() {
							rulev1.ResourceUniqueCounter.WarningResources++
						}
						ruleResponse := reporthandling.RuleResponse{}
						ruleResponse.Rulename = rulev2.GetName()
						ruleResponse.FailedPaths = rulev2.FailedPaths
						ruleResponse.RuleStatus = string(rulev2.GetStatus(&v1.Filters{FrameworkNames: []string{fwv2.GetName()}}).Status())
						if len(rulev2.Exception) > 0 {
							ruleResponse.Exception = &rulev2.Exception[0]
						}

						if fullRessource, ok := opaSessionObj.AllResources[resourceID]; ok {
							ruleResponse.AlertObject.K8SApiObjects = append(ruleResponse.AlertObject.K8SApiObjects, fullRessource.GetObject())
						}
						rulev1.RuleResponses = append(rulev1.RuleResponses, ruleResponse)
						rulev1.ListInputKinds = append(rulev1.ListInputKinds, resourceID)
						crv1.RuleReports = append(crv1.RuleReports, rulev1)
					}
				}
			}

		}
		fwv1.ControlReports = append(fwv1.ControlReports, crv1)

		frameworks = append(frameworks, fwv1)

	}

	for f := range frameworks {
		// // set exceptions
		// exceptions.SetFrameworkExceptions(&opap.PostureReport.FrameworkReports[f], opap.Exceptions, cautils.ClusterName)

		// // set counters
		// reporthandling.SetUniqueResourcesCounter(&opap.PostureReport.FrameworkReports[f])

		// set default score
		reporthandling.SetDefaultScore(&frameworks[f])
	}

	// update score
	scoreutil := score.NewScore(opaSessionObj.AllResources)
	scoreutil.Calculate(frameworks)

	opaSessionObj.PostureReport.FrameworkReports = frameworks

}
