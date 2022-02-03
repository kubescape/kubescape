package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	ksscore "github.com/armosec/kubescape/score"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/reporthandling/apis"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/open-policy-agent/opa/storage"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"

	"github.com/armosec/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const ScoreConfigPath = "/resources/config"

type OPAProcessorHandler struct {
	processedPolicy      *chan *cautils.OPASessionObj
	reportResults        *chan *cautils.OPASessionObj
	regoDependenciesData *resources.RegoDependenciesData
}

type OPAProcessor struct {
	*cautils.OPASessionObj
	regoDependenciesData *resources.RegoDependenciesData
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
	}
	return &OPAProcessor{
		OPASessionObj:        sessionObj,
		regoDependenciesData: regoDependenciesData,
	}
}

func NewOPAProcessorHandler(processedPolicy, reportResults *chan *cautils.OPASessionObj) *OPAProcessorHandler {
	return &OPAProcessorHandler{
		processedPolicy:      processedPolicy,
		reportResults:        reportResults,
		regoDependenciesData: resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), cautils.ClusterName),
	}
}

func (opaHandler *OPAProcessorHandler) ProcessRulesListenner() {

	for {
		opaSessionObj := <-*opaHandler.processedPolicy
		opap := NewOPAProcessor(opaSessionObj, opaHandler.regoDependenciesData)

		policies := ConvertFrameworksToPolicies(opap.Frameworks, cautils.BuildNumber)

		ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Frameworks, policies)

		// process
		if err := opap.Process(policies); err != nil {
			logger.L().Error(err.Error())
		}

		// edit results
		opap.updateResults()

		//TODO: review this location
		scorewrapper := ksscore.NewScoreWrapper(opaSessionObj)
		scorewrapper.Calculate(ksscore.EPostureReportV2)
		// report
		*opaHandler.reportResults <- opaSessionObj
	}
}

func (opap *OPAProcessor) Process(policies *cautils.Policies) error {
	logger.L().Info(fmt.Sprintf("Scanning cluster %s", cautils.ClusterName))

	cautils.StartSpinner()

	var errs error
	for _, control := range policies.Controls {

		resourcesAssociatedControl, err := opap.processControl(&control)
		if err != nil {
			logger.L().Error(err.Error())
		}
		// update resources with latest results
		if len(resourcesAssociatedControl) != 0 {
			for resourceID, controlResult := range resourcesAssociatedControl {
				if _, ok := opap.ResourcesResult[resourceID]; !ok {
					opap.ResourcesResult[resourceID] = resourcesresults.Result{ResourceID: resourceID}
				}
				t := opap.ResourcesResult[resourceID]
				t.AssociatedControls = append(t.AssociatedControls, controlResult)
				opap.ResourcesResult[resourceID] = t
			}
		}
	}

	opap.Report.ReportGenerationTime = time.Now().UTC()

	cautils.StopSpinner()
	logger.L().Success(fmt.Sprintf("Done scanning cluster %s", cautils.ClusterName))
	return errs
}

func (opap *OPAProcessor) processControl(control *reporthandling.Control) (map[string]resourcesresults.ResourceAssociatedControl, error) {
	var errs error

	resourcesAssociatedControl := make(map[string]resourcesresults.ResourceAssociatedControl)

	// ruleResults := make(map[string][]resourcesresults.ResourceAssociatedRule)
	for i := range control.Rules {
		resourceAssociatedRule, err := opap.processRule(&control.Rules[i])
		if err != nil {
			logger.L().Error(err.Error())
			continue
		}

		// append failed rules to controls
		if len(resourceAssociatedRule) != 0 {
			for resourceID, ruleResponse := range resourceAssociatedRule {

				controlResult := resourcesresults.ResourceAssociatedControl{}
				controlResult.SetID(control.ControlID)
				controlResult.SetName(control.Name)

				if _, ok := resourcesAssociatedControl[resourceID]; ok {
					controlResult.ResourceAssociatedRules = resourcesAssociatedControl[resourceID].ResourceAssociatedRules
				}
				if ruleResponse != nil {
					controlResult.ResourceAssociatedRules = append(controlResult.ResourceAssociatedRules, *ruleResponse)
				}
				resourcesAssociatedControl[resourceID] = controlResult
			}
		}
	}

	return resourcesAssociatedControl, errs
}

func (opap *OPAProcessor) processRule(rule *reporthandling.PolicyRule) (map[string]*resourcesresults.ResourceAssociatedRule, error) {

	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlInputs(rule.ConfigInputs) // get store

	inputResources, err := reporthandling.RegoResourcesAggregator(rule, getAllSupportedObjects(opap.K8SResources, opap.AllResources, rule))
	if err != nil {
		return nil, fmt.Errorf("error getting aggregated k8sObjects: %s", err.Error())
	}
	if len(inputResources) == 0 {
		return nil, nil // no resources found for testing
	}

	inputRawResources := workloadinterface.ListMetaToMap(inputResources)

	resources := map[string]*resourcesresults.ResourceAssociatedRule{}
	// the failed resources are a subgroup of the enumeratedData, so we store the enumeratedData like it was the input data
	enumeratedData, err := opap.enumerateData(rule, inputRawResources)
	if err != nil {
		return nil, err
	}
	inputResources = objectsenvelopes.ListMapToMeta(enumeratedData)
	for i := range inputResources {
		resources[inputResources[i].GetID()] = &resourcesresults.ResourceAssociatedRule{
			Name:                  rule.Name,
			ControlConfigurations: postureControlInputs,
			Status:                apis.StatusPassed,
		}
		opap.AllResources[inputResources[i].GetID()] = inputResources[i]
	}

	ruleResponses, err := opap.runOPAOnSingleRule(rule, inputRawResources, ruleData, postureControlInputs)
	if err != nil {
		// TODO - Handle error
		logger.L().Error(err.Error())
	} else {
		// ruleResponse to ruleResult
		for i := range ruleResponses {
			failedResources := objectsenvelopes.ListMapToMeta(ruleResponses[i].GetFailedResources())
			for j := range failedResources {
				ruleResult := &resourcesresults.ResourceAssociatedRule{}
				if r, k := resources[failedResources[j].GetID()]; k {
					ruleResult = r
				}

				ruleResult.Status = apis.StatusFailed
				for j := range ruleResponses[i].FailedPaths {
					ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FailedPath: ruleResponses[i].FailedPaths[j]})
				}
				for j := range ruleResponses[i].FixPaths {
					ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FixPath: ruleResponses[i].FixPaths[j]})
				}
				resources[failedResources[j].GetID()] = ruleResult
			}
		}
	}

	return resources, err
}

func (opap *OPAProcessor) runOPAOnSingleRule(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, postureControlInputs map[string][]string) ([]reporthandling.RuleResponse, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(rule, k8sObjects, getRuleData, postureControlInputs)
	default:
		return nil, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

func (opap *OPAProcessor) runRegoOnK8s(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, postureControlInputs map[string][]string) ([]reporthandling.RuleResponse, error) {

	// compile modules
	modules, err := getRuleDependencies()
	if err != nil {
		return nil, fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}
	modules[rule.Name] = getRuleData(rule)
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("in 'runRegoOnSingleRule', failed to compile rule, name: %s, reason: %s", rule.Name, err.Error())
	}

	store, err := resources.TOStorage(postureControlInputs)
	if err != nil {
		return nil, err
	}

	// Eval
	results, err := opap.regoEval(k8sObjects, compiled, &store)
	if err != nil {
		logger.L().Error(err.Error())
	}

	return results, nil
}

func (opap *OPAProcessor) regoEval(inputObj []map[string]interface{}, compiledRego *ast.Compiler, store *storage.Store) ([]reporthandling.RuleResponse, error) {
	// opap.regoDependenciesData.PostureControlInputs

	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(*store),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	results, err := reporthandling.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}

func (opap *OPAProcessor) enumerateData(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) ([]map[string]interface{}, error) {

	if ruleEnumeratorData(rule) == "" {
		return k8sObjects, nil
	}
	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlInputs(rule.ConfigInputs)

	ruleResponse, err := opap.runOPAOnSingleRule(rule, k8sObjects, ruleEnumeratorData, postureControlInputs)
	if err != nil {
		return nil, err
	}
	failedResources := []map[string]interface{}{}
	for _, ruleResponse := range ruleResponse {
		failedResources = append(failedResources, ruleResponse.GetFailedResources()...)
	}
	return failedResources, nil
}
