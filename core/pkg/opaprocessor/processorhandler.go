package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/pkg/score"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"

	"github.com/open-policy-agent/opa/storage"

	"github.com/kubescape/k8s-interface/workloadinterface"

	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const ScoreConfigPath = "/resources/config"

type OPAProcessor struct {
	regoDependenciesData *resources.RegoDependenciesData
	*cautils.OPASessionObj
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
func (opap *OPAProcessor) ProcessRulesListenner() error {

	policies := ConvertFrameworksToPolicies(opap.Policies, cautils.BuildNumber)

	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, policies)

	// process
	if err := opap.Process(policies); err != nil {
		logger.L().Error(err.Error())
		// Return error?
	}

	// edit results
	opap.updateResults()

	//TODO: review this location
	scorewrapper := score.NewScoreWrapper(opap.OPASessionObj)
	scorewrapper.Calculate(score.EPostureReportV2)

	return nil
}

func (opap *OPAProcessor) Process(policies *cautils.Policies) error {
	opap.loggerStartScanning()

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

	opap.loggerDoneScanning()

	return errs
}

func (opap *OPAProcessor) loggerStartScanning() {
	targetScan := opap.OPASessionObj.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().Info("Scanning", helpers.String(targetScan.String(), cautils.ClusterName))
	} else {
		logger.L().Info("Scanning " + targetScan.String())
	}
}

func (opap *OPAProcessor) loggerDoneScanning() {
	targetScan := opap.OPASessionObj.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().Success("Done scanning", helpers.String(targetScan.String(), cautils.ClusterName))
	} else {
		logger.L().Success("Done scanning " + targetScan.String())
	}
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

	inputResources, err := reporthandling.RegoResourcesAggregator(rule, getAllSupportedObjects(opap.K8SResources, opap.ArmoResource, opap.AllResources, rule))
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
				if ruleResponses[i].FixCommand != "" {
					ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FixCommand: ruleResponses[i].FixCommand})
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
