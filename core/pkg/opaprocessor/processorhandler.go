package opaprocessor

import (
	"context"
	"fmt"
	"sync"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/score"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"go.opentelemetry.io/otel"
	"golang.org/x/exp/slices"
)

const ScoreConfigPath = "/resources/config"

type IJobProgressNotificationClient interface {
	Start(allSteps int)
	ProgressJob(step int, message string)
	Stop()
}

// OPAProcessor processes Open Policy Agent rules.
type OPAProcessor struct {
	clusterName          string
	regoDependenciesData *resources.RegoDependenciesData
	*cautils.OPASessionObj
	opaRegisterOnce sync.Once
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData, clusterName string) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
		regoDependenciesData.DataControlInputs = sessionObj.RegoInputData.DataControlInputs
	}

	return &OPAProcessor{
		OPASessionObj:        sessionObj,
		regoDependenciesData: regoDependenciesData,
		clusterName:          clusterName,
	}
}

func (opap *OPAProcessor) ProcessRulesListener(ctx context.Context, progressListener IJobProgressNotificationClient) error {
	scanningScope := cautils.GetScanningScope(opap.Metadata.ContextMetadata)
	opap.OPASessionObj.AllPolicies = convertFrameworksToPolicies(opap.Policies, opap.ExcludedRules, scanningScope)

	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.OPASessionObj.AllPolicies)

	// process
	if err := opap.Process(ctx, opap.OPASessionObj.AllPolicies, progressListener); err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
		// Return error?
	}

	// edit results
	opap.updateResults(ctx)

	//TODO: review this location
	scorewrapper := score.NewScoreWrapper(opap.OPASessionObj)
	_ = scorewrapper.Calculate(score.EPostureReportV2)

	return nil
}

// Process OPA policies (rules) on all configured controls.
func (opap *OPAProcessor) Process(ctx context.Context, policies *cautils.Policies, progressListener IJobProgressNotificationClient) error {
	ctx, span := otel.Tracer("").Start(ctx, "OPAProcessor.Process")
	defer span.End()
	opap.loggerStartScanning()
	defer opap.loggerDoneScanning()

	if progressListener != nil {
		progressListener.Start(len(policies.Controls))
		defer progressListener.Stop()
	}

	for _, toPin := range policies.Controls {
		if progressListener != nil {
			progressListener.ProgressJob(1, fmt.Sprintf("Control: %s", toPin.ControlID))
		}

		control := toPin

		resourcesAssociatedControl, err := opap.processControl(ctx, &control)
		if err != nil {
			logger.L().Ctx(ctx).Warning(err.Error())
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

	return nil
}

func (opap *OPAProcessor) loggerStartScanning() {
	targetScan := opap.OPASessionObj.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().Start("Scanning", helpers.String(targetScan.String(), opap.clusterName))
	} else {
		logger.L().Start("Scanning " + targetScan.String())
	}
}

func (opap *OPAProcessor) loggerDoneScanning() {
	targetScan := opap.OPASessionObj.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().StopSuccess("Done scanning", helpers.String(targetScan.String(), opap.clusterName))
	} else {
		logger.L().StopSuccess("Done scanning " + targetScan.String())
	}
}

// processControl processes all the rules for a given control
//
// NOTE: the call to processControl no longer mutates the state of the current OPAProcessor instance,
// but returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processControl(ctx context.Context, control *reporthandling.Control) (map[string]resourcesresults.ResourceAssociatedControl, error) {
	resourcesAssociatedControl := make(map[string]resourcesresults.ResourceAssociatedControl)

	for i := range control.Rules {
		resourceAssociatedRule, err := opap.processRule(ctx, &control.Rules[i], control.FixedInput)
		if err != nil {
			logger.L().Ctx(ctx).Warning(err.Error())
			continue
		}

		// append failed rules to controls
		for resourceID, ruleResponse := range resourceAssociatedRule {
			var controlResult resourcesresults.ResourceAssociatedControl
			controlResult.SetID(control.ControlID)
			controlResult.SetName(control.Name)

			if associatedControl, ok := resourcesAssociatedControl[resourceID]; ok {
				controlResult.ResourceAssociatedRules = associatedControl.ResourceAssociatedRules
			}

			if ruleResponse != nil {
				controlResult.ResourceAssociatedRules = append(controlResult.ResourceAssociatedRules, *ruleResponse)
			}

			if control, ok := opap.AllPolicies.Controls[control.ControlID]; ok {
				controlResult.SetStatus(control)
			}
			resourcesAssociatedControl[resourceID] = controlResult
		}
	}

	return resourcesAssociatedControl, nil
}

// processRule processes a single policy rule, with some extra fixed control inputs.
//
// NOTE: processRule no longer mutates the state of the current OPAProcessor instance,
// and returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processRule(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string) (map[string]*resourcesresults.ResourceAssociatedRule, error) {
	resources := make(map[string]*resourcesresults.ResourceAssociatedRule)

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, fixedControlInputs)

	resourcesPerNS := getAllSupportedObjects(opap.K8SResources, opap.ExternalResources, opap.AllResources, rule)
	for i := range resourcesPerNS {
		resourceToScan := resourcesPerNS[i]
		if _, ok := resourcesPerNS[clusterScope]; ok && i != clusterScope {
			resourceToScan = append(resourceToScan, resourcesPerNS[clusterScope]...)
		}
		inputResources, err := reporthandling.RegoResourcesAggregator(
			rule,
			resourceToScan, // NOTE: this uses the initial snapshot of AllResources
		)
		if err != nil {
			continue
		}

		if len(inputResources) == 0 {
			continue // no resources found for testing
		}

		inputRawResources := workloadinterface.ListMetaToMap(inputResources)

		// the failed resources are a subgroup of the enumeratedData, so we store the enumeratedData like it was the input data
		enumeratedData, err := opap.enumerateData(ctx, rule, inputRawResources)
		if err != nil {
			continue
		}

		inputResources = objectsenvelopes.ListMapToMeta(enumeratedData)

		for i, inputResource := range inputResources {
			resources[inputResource.GetID()] = &resourcesresults.ResourceAssociatedRule{
				Name:                  rule.Name,
				ControlConfigurations: ruleRegoDependenciesData.PostureControlInputs,
				Status:                apis.StatusPassed,
			}
			opap.AllResources[inputResource.GetID()] = inputResources[i]
		}

		ruleResponses, err := opap.runOPAOnSingleRule(ctx, rule, inputRawResources, ruleData, ruleRegoDependenciesData)
		if err != nil {
			continue
			// return resources, allResources, err
		}

		// ruleResponse to ruleResult
		for _, ruleResponse := range ruleResponses {
			failedResources := objectsenvelopes.ListMapToMeta(ruleResponse.GetFailedResources())
			for _, failedResource := range failedResources {
				var ruleResult *resourcesresults.ResourceAssociatedRule
				if r, found := resources[failedResource.GetID()]; found {
					ruleResult = r
				} else {
					ruleResult = &resourcesresults.ResourceAssociatedRule{
						Paths: make([]armotypes.PosturePaths, 0, len(ruleResponse.FailedPaths)+len(ruleResponse.FixPaths)+1),
					}
				}

				ruleResult.SetStatus(apis.StatusFailed, nil)
				ruleResult.Paths = appendPaths(ruleResult.Paths, ruleResponse.AssistedRemediation, failedResource.GetID())
				// if ruleResponse has relatedObjects, add it to ruleResult
				if len(ruleResponse.RelatedObjects) > 0 {
					for _, relatedObject := range ruleResponse.RelatedObjects {
						wl := objectsenvelopes.NewObject(relatedObject.Object)
						if wl != nil {
							// avoid adding duplicate related resource IDs
							if !slices.Contains(ruleResult.RelatedResourcesIDs, wl.GetID()) {
								ruleResult.RelatedResourcesIDs = append(ruleResult.RelatedResourcesIDs, wl.GetID())
							}
							ruleResult.Paths = appendPaths(ruleResult.Paths, relatedObject.AssistedRemediation, wl.GetID())
						}
					}
				}

				resources[failedResource.GetID()] = ruleResult
			}
		}
	}
	return resources, nil
}

// appendPaths appends the failedPaths, fixPaths and fixCommand to the paths slice with the resourceID
func appendPaths(paths []armotypes.PosturePaths, assistedRemediation reporthandling.AssistedRemediation, resourceID string) []armotypes.PosturePaths {
	// TODO - deprecate failedPaths after all controls support reviewPaths and deletePaths
	for _, failedPath := range assistedRemediation.FailedPaths {
		paths = append(paths, armotypes.PosturePaths{ResourceID: resourceID, FailedPath: failedPath})
	}
	for _, deletePath := range assistedRemediation.DeletePaths {
		paths = append(paths, armotypes.PosturePaths{ResourceID: resourceID, DeletePath: deletePath})
	}
	for _, reviewPath := range assistedRemediation.ReviewPaths {
		paths = append(paths, armotypes.PosturePaths{ResourceID: resourceID, ReviewPath: reviewPath})
	}
	for _, fixPath := range assistedRemediation.FixPaths {
		paths = append(paths, armotypes.PosturePaths{ResourceID: resourceID, FixPath: fixPath})
	}
	if assistedRemediation.FixCommand != "" {
		paths = append(paths, armotypes.PosturePaths{ResourceID: resourceID, FixCommand: assistedRemediation.FixCommand})
	}
	return paths
}

func (opap *OPAProcessor) runOPAOnSingleRule(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(ctx, rule, k8sObjects, getRuleData, ruleRegoDependenciesData)
	default:
		return nil, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

// runRegoOnK8s compiles an OPA PolicyRule and evaluates its against k8s
func (opap *OPAProcessor) runRegoOnK8s(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	modules, err := getRuleDependencies(ctx)
	if err != nil {
		return nil, fmt.Errorf("rule: '%s', %s", rule.Name, err.Error())
	}

	opap.opaRegisterOnce.Do(func() {
		// register signature verification methods for the OPA ast engine (since these are package level symbols, we do it only once)
		rego.RegisterBuiltin2(cosignVerifySignatureDeclaration, cosignVerifySignatureDefinition)
		rego.RegisterBuiltin1(cosignHasSignatureDeclaration, cosignHasSignatureDefinition)
		rego.RegisterBuiltin1(imageNameNormalizeDeclaration, imageNameNormalizeDefinition)
	})

	modules[rule.Name] = getRuleData(rule)

	// NOTE: OPA module compilation is the most resource-intensive operation.
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("in 'runRegoOnK8s', failed to compile rule, name: %s, reason: %w", rule.Name, err)
	}

	store, err := ruleRegoDependenciesData.TOStorage()
	if err != nil {
		return nil, err
	}

	// Eval
	results, err := opap.regoEval(ctx, k8sObjects, compiled, &store)
	if err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
	}

	return results, nil
}

func (opap *OPAProcessor) regoEval(ctx context.Context, inputObj []map[string]interface{}, compiledRego *ast.Compiler, store *storage.Store) ([]reporthandling.RuleResponse, error) {
	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(*store),
	)

	// Run evaluation
	resultSet, err := rego.Eval(ctx)
	if err != nil {
		return nil, err
	}
	results, err := reporthandling.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}

func (opap *OPAProcessor) enumerateData(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]interface{}) ([]map[string]interface{}, error) {
	if ruleEnumeratorData(rule) == "" {
		return k8sObjects, nil
	}

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, nil)
	ruleResponse, err := opap.runOPAOnSingleRule(ctx, rule, k8sObjects, ruleEnumeratorData, ruleRegoDependenciesData)
	if err != nil {
		return nil, err
	}

	failedResources := make([]map[string]interface{}, 0, len(ruleResponse))
	for _, ruleResponse := range ruleResponse {
		failedResources = append(failedResources, ruleResponse.GetFailedResources()...)
	}

	return failedResources, nil
}

// makeRegoDeps builds a resources.RegoDependenciesData struct for the current cloud provider.
//
// If some extra fixedControlInputs are provided, they are merged into the "posture" control inputs.
func (opap *OPAProcessor) makeRegoDeps(configInputs []reporthandling.ControlConfigInputs, fixedControlInputs map[string][]string) resources.RegoDependenciesData {
	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlConfigInputs(configInputs) // get store

	// merge configurable control input and fixed control input
	for k, v := range fixedControlInputs {
		postureControlInputs[k] = v
	}

	dataControlInputs := map[string]string{
		"cloudProvider": opap.OPASessionObj.Report.ClusterCloudProvider,
	}

	return resources.RegoDependenciesData{
		DataControlInputs:    dataControlInputs,
		PostureControlInputs: postureControlInputs,
	}
}
