package opaprocessor

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/score"
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

type IJobProgressNotificationClient interface {
	Start(allSteps int)
	ProgressJob(step int, message string)
	Stop()
}

type OPAProcessor struct {
	regoDependenciesData *resources.RegoDependenciesData
	*cautils.OPASessionObj
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
		regoDependenciesData.DataControlInputs = sessionObj.RegoInputData.DataControlInputs
	}
	return &OPAProcessor{
		OPASessionObj:        sessionObj,
		regoDependenciesData: regoDependenciesData,
	}
}
func (opap *OPAProcessor) ProcessRulesListenner(progressListener IJobProgressNotificationClient) error {

	opap.OPASessionObj.AllPolicies = ConvertFrameworksToPolicies(opap.Policies, cautils.BuildNumber)

	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.OPASessionObj.AllPolicies)

	// process
	if err := opap.Process(opap.OPASessionObj.AllPolicies, progressListener); err != nil {
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

func (opap *OPAProcessor) Process(policies *cautils.Policies, progressListener IJobProgressNotificationClient) error {
	opap.loggerStartScanning()

	if progressListener != nil {
		progressListener.Start(len(policies.Controls))
		defer progressListener.Stop()
	}

	for _, toPin := range policies.Controls {
		if progressListener != nil {
			progressListener.ProgressJob(1, fmt.Sprintf("Control %s", toPin.ControlID))
		}

		control := toPin

		resourcesAssociatedControl, err := opap.processControl(&control)
		if err != nil {
			logger.L().Error(err.Error())
		}

		if len(resourcesAssociatedControl) == 0 {
			continue
		}

		// update resources with latest results
		for resourceID, controlResult := range resourcesAssociatedControl {
			if _, ok := opap.ResourcesResult[resourceID]; !ok {
				opap.ResourcesResult[resourceID] = resourcesresults.Result{ResourceID: resourceID}
			}
			t := opap.ResourcesResult[resourceID]
			t.AssociatedControls = append(t.AssociatedControls, controlResult)
			opap.ResourcesResult[resourceID] = t
		}
	}

	opap.Report.ReportGenerationTime = time.Now().UTC()

	opap.loggerDoneScanning()

	return nil
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
		resourceAssociatedRule, err := opap.processRule(&control.Rules[i], control.FixedInput)
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

func (opap *OPAProcessor) processRule(rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string) (map[string]*resourcesresults.ResourceAssociatedRule, error) {

	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlInputs(rule.ConfigInputs) // get store
	dataControlInputs := map[string]string{"cloudProvider": opap.OPASessionObj.Report.ClusterCloudProvider}

	// Merge configurable control input and fixed control input
	for k, v := range fixedControlInputs {
		postureControlInputs[k] = v
	}

	RuleRegoDependenciesData := resources.RegoDependenciesData{DataControlInputs: dataControlInputs,
		PostureControlInputs: postureControlInputs}

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

	ruleResponses, err := opap.runOPAOnSingleRule(rule, inputRawResources, ruleData, RuleRegoDependenciesData)
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

func (opap *OPAProcessor) runOPAOnSingleRule(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(rule, k8sObjects, getRuleData, ruleRegoDependenciesData)
	default:
		return nil, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

func (opap *OPAProcessor) runRegoOnK8s(rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {

	// compile modules
	modules, err := getRuleDependencies()
	if err != nil {
		return nil, fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}
	rego.RegisterBuiltin2(cosignVerifySignatureDeclaration, cosignVerifySignatureDefinition)
	rego.RegisterBuiltin1(cosignHasSignatureDeclaration, cosignHasSignatureDefinition)
	modules[rule.Name] = getRuleData(rule)
	compiled, err := ast.CompileModules(modules)

	if err != nil {
		return nil, fmt.Errorf("in 'runRegoOnSingleRule', failed to compile rule, name: %s, reason: %s", rule.Name, err.Error())
	}

	store, err := ruleRegoDependenciesData.TOStorage()
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
	dataControlInputs := map[string]string{"cloudProvider": opap.OPASessionObj.Report.ClusterCloudProvider}

	RuleRegoDependenciesData := resources.RegoDependenciesData{DataControlInputs: dataControlInputs,
		PostureControlInputs: postureControlInputs}

	ruleResponse, err := opap.runOPAOnSingleRule(rule, k8sObjects, ruleEnumeratorData, RuleRegoDependenciesData)
	if err != nil {
		return nil, err
	}
	failedResources := []map[string]interface{}{}
	for _, ruleResponse := range ruleResponse {
		failedResources = append(failedResources, ruleResponse.GetFailedResources()...)
	}
	return failedResources, nil
}
