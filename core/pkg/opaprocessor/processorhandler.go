package opaprocessor

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/score"
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
	"golang.org/x/sync/errgroup"
)

const ScoreConfigPath = "/resources/config"

type IJobProgressNotificationClient interface {
	Start(allSteps int)
	ProgressJob(step int, message string)
	Stop()
}

const (
	heuristicAllocResources = 100
	heuristicAllocControls  = 100
)

// OPAProcessor processes Open Policy Agent rules.
type OPAProcessor struct {
	regoDependenciesData *resources.RegoDependenciesData
	*cautils.OPASessionObj
	opaRegisterOnce sync.Once
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

func (opap *OPAProcessor) ProcessRulesListener(ctx context.Context, progressListener IJobProgressNotificationClient) error {
	opap.OPASessionObj.AllPolicies = ConvertFrameworksToPolicies(opap.Policies, cautils.BuildNumber)

	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.OPASessionObj.AllPolicies)

	maxGoRoutines, err := parseIntEnvVar("RULE_PROCESSING_GOMAXPROCS", 2*runtime.NumCPU())
	if err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
	}

	// process
	if err := opap.Process(ctx, opap.OPASessionObj.AllPolicies, progressListener, maxGoRoutines); err != nil {
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
func (opap *OPAProcessor) Process(ctx context.Context, policies *cautils.Policies, progressListener IJobProgressNotificationClient, maxGoRoutines int) error {
	ctx, span := otel.Tracer("").Start(ctx, "OPAProcessor.Process")
	defer span.End()
	opap.loggerStartScanning()
	defer opap.loggerDoneScanning()

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	if progressListener != nil {
		progressListener.Start(len(policies.Controls))
		defer progressListener.Stop()
	}

	// results to collect from controls being processed in parallel
	type results struct {
		resourceAssociatedControl map[string]resourcesresults.ResourceAssociatedControl
		allResources              map[string]workloadinterface.IMetadata
	}

	resultsChan := make(chan results)
	controlsGroup, groupCtx := errgroup.WithContext(ctx)
	controlsGroup.SetLimit(maxGoRoutines)

	allResources := make(map[string]workloadinterface.IMetadata, max(len(opap.AllResources), heuristicAllocResources))
	for k, v := range opap.AllResources {
		allResources[k] = v
	}

	var resultsCollector sync.WaitGroup
	resultsCollector.Add(1)
	go func() {
		// collects the results from processing all rules for all controls.
		//
		// NOTE: since policies.Controls is a map, iterating over it doesn't guarantee any
		// specific ordering. Therefore, if a conflict is possible on resources, e.g. 2 rules,
		// referencing the same resource, the eventual result of the merge is not guaranteed to be
		// stable. This behavior is consistent with the previous (unparallelized) processing.
		defer resultsCollector.Done()

		for result := range resultsChan {
			// merge both maps in parallel
			var merger sync.WaitGroup
			merger.Add(1)
			go func() {
				// merge all resources
				defer merger.Done()
				for k, v := range result.allResources {
					allResources[k] = v
				}
			}()

			merger.Add(1)
			go func() {
				defer merger.Done()
				// update resources with latest results
				for resourceID, controlResult := range result.resourceAssociatedControl {
					result, found := opap.ResourcesResult[resourceID]
					if !found {
						result = resourcesresults.Result{ResourceID: resourceID}
					}
					result.AssociatedControls = append(result.AssociatedControls, controlResult)
					opap.ResourcesResult[resourceID] = result
				}
			}()

			merger.Wait()
		}
	}()

	// processes rules for all controls in parallel
	for _, controlToPin := range policies.Controls {
		if progressListener != nil {
			progressListener.ProgressJob(1, fmt.Sprintf("Control: %s", controlToPin.ControlID))
		}

		control := controlToPin

		controlsGroup.Go(func() error {
			resourceAssociatedControl, allResourcesFromControl, err := opap.processControl(groupCtx, &control)
			if err != nil {
				logger.L().Ctx(groupCtx).Warning(err.Error())
			}

			select {
			case resultsChan <- results{
				resourceAssociatedControl: resourceAssociatedControl,
				allResources:              allResourcesFromControl,
			}:
			case <-groupCtx.Done(): // interrupted (NOTE: at this moment, this never happens since errors are muted)
				return groupCtx.Err()
			}

			return nil
		})
	}

	// wait for all results from all rules to be collected
	err := controlsGroup.Wait()
	close(resultsChan)
	resultsCollector.Wait()

	if err != nil {
		return err
	}

	// merge the final result in resources
	for k, v := range allResources {
		opap.AllResources[k] = v
	}
	opap.Report.ReportGenerationTime = time.Now().UTC()

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

// processControl processes all the rules for a given control
//
// NOTE: the call to processControl no longer mutates the state of the current OPAProcessor instance,
// but returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processControl(ctx context.Context, control *reporthandling.Control) (map[string]resourcesresults.ResourceAssociatedControl, map[string]workloadinterface.IMetadata, error) {
	resourcesAssociatedControl := make(map[string]resourcesresults.ResourceAssociatedControl, heuristicAllocControls)
	allResources := make(map[string]workloadinterface.IMetadata, heuristicAllocResources)

	for i := range control.Rules {
		resourceAssociatedRule, allResourcesFromRule, err := opap.processRule(ctx, &control.Rules[i], control.FixedInput)
		if err != nil {
			logger.L().Ctx(ctx).Warning(err.Error())
			continue
		}

		// merge all resources for all processed rules in this control
		for k, v := range allResourcesFromRule {
			allResources[k] = v
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

	return resourcesAssociatedControl, allResources, nil
}

// processRule processes a single policy rule, with some extra fixed control inputs.
//
// NOTE: processRule no longer mutates the state of the current OPAProcessor instance,
// and returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processRule(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string) (map[string]*resourcesresults.ResourceAssociatedRule, map[string]workloadinterface.IMetadata, error) {
	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ConfigInputs, fixedControlInputs)

	inputResources, err := reporthandling.RegoResourcesAggregator(
		rule,
		getAllSupportedObjects(opap.K8SResources, opap.ArmoResource, opap.AllResources, rule), // NOTE: this uses the initial snapshot of AllResources
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting aggregated k8sObjects: %w", err)
	}

	if len(inputResources) == 0 {
		return nil, nil, nil // no resources found for testing
	}

	inputRawResources := workloadinterface.ListMetaToMap(inputResources)

	// the failed resources are a subgroup of the enumeratedData, so we store the enumeratedData like it was the input data
	enumeratedData, err := opap.enumerateData(ctx, rule, inputRawResources)
	if err != nil {
		return nil, nil, err
	}

	inputResources = objectsenvelopes.ListMapToMeta(enumeratedData)
	resources := make(map[string]*resourcesresults.ResourceAssociatedRule, len(inputResources))
	allResources := make(map[string]workloadinterface.IMetadata, len(inputResources))

	for i, inputResource := range inputResources {
		resources[inputResource.GetID()] = &resourcesresults.ResourceAssociatedRule{
			Name:                  rule.Name,
			ControlConfigurations: ruleRegoDependenciesData.PostureControlInputs,
			Status:                apis.StatusPassed,
		}
		allResources[inputResource.GetID()] = inputResources[i]
	}

	ruleResponses, err := opap.runOPAOnSingleRule(ctx, rule, inputRawResources, ruleData, ruleRegoDependenciesData)
	if err != nil {
		return resources, allResources, err
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
			for _, failedPath := range ruleResponse.FailedPaths {
				ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FailedPath: failedPath})
			}

			for _, fixPath := range ruleResponse.FixPaths {
				ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FixPath: fixPath})
			}

			if ruleResponse.FixCommand != "" {
				ruleResult.Paths = append(ruleResult.Paths, armotypes.PosturePaths{FixCommand: ruleResponse.FixCommand})
			}
			// if ruleResponse has relatedObjects, add it to ruleResult
			if len(ruleResponse.RelatedObjects) > 0 {
				for _, relatedObject := range ruleResponse.RelatedObjects {
					wl := objectsenvelopes.NewObject(relatedObject.Object)
					if wl != nil {
						ruleResult.RelatedResourcesIDs = append(ruleResult.RelatedResourcesIDs, wl.GetID())
					}
				}
			}

			resources[failedResource.GetID()] = ruleResult
		}
	}

	return resources, allResources, nil
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

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ConfigInputs, nil)
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
func (opap *OPAProcessor) makeRegoDeps(configInputs []string, fixedControlInputs map[string][]string) resources.RegoDependenciesData {
	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlInputs(configInputs) // get store

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

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}
