package opaprocessor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/score"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	opaprint "github.com/open-policy-agent/opa/v1/topdown/print"
	"go.opentelemetry.io/otel"
	"k8s.io/client-go/tools/record"
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
	exceptionEventRecorder record.EventRecorder
	opaRegisterOnce        sync.Once
	excludeNamespaces      []string
	includeNamespaces      []string
	printEnabled           bool
	compiledModules        map[string]*ast.Compiler
	compiledMu             sync.RWMutex
	// ControlTimeout, when non-zero, bounds the evaluation time of a single
	// control. If exceeded, the control is recorded as not evaluated instead
	// of stalling or aborting the whole scan.
	ControlTimeout time.Duration
	// TimedOutControls maps controlID to the reason its evaluation was
	// aborted after exceeding ControlTimeout.
	TimedOutControls map[string]string
}

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData, clusterName string, excludeNamespaces string, includeNamespaces string, enableRegoPrint bool, exceptionEventRecorder record.EventRecorder) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
		regoDependenciesData.DataControlInputs = sessionObj.RegoInputData.DataControlInputs
	}

	return &OPAProcessor{
		OPASessionObj:          sessionObj,
		regoDependenciesData:   regoDependenciesData,
		clusterName:            clusterName,
		exceptionEventRecorder: exceptionEventRecorder,
		excludeNamespaces:      split(excludeNamespaces),
		includeNamespaces:      split(includeNamespaces),
		printEnabled:           enableRegoPrint,
		compiledModules:        make(map[string]*ast.Compiler),
		TimedOutControls:       make(map[string]string),
	}
}

func (opap *OPAProcessor) ProcessRulesListener(ctx context.Context, progressListener IJobProgressNotificationClient) error {
	scanningScope := cautils.GetScanningScope(opap.Metadata.ContextMetadata)
	opap.AllPolicies = convertFrameworksToPolicies(opap.Policies, opap.ExcludedRules, scanningScope)

	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.AllPolicies)

	// process
	processErr := opap.Process(ctx, opap.AllPolicies, progressListener)
	if processErr != nil {
		logger.L().Ctx(ctx).Warning(processErr.Error())
	}

	// rebuild ScanCoverage so controls that timed out during evaluation
	// (recorded in TimedOutControls by markControlTimedOut) are reflected in
	// NotEvaluatedControls alongside any collection-phase failures
	opap.ScanCoverage = cautils.BuildScanCoverage(opap.InfoMap, opap.ResourceToControlsMap, opap.TimedOutControls, opap.PartialGVRFailures, opap.PolicyDegradations)
	opap.ScanCoverage.ComputeCoverageScore(len(opap.Report.SummaryDetails.Controls))

	// edit results
	opap.updateResults(ctx)

	opap.markTimedOutControlsSkipped()

	scorewrapper := score.NewScoreWrapper(opap.OPASessionObj)
	if err := scorewrapper.Calculate(score.EPostureReportV2); err != nil {
		logger.L().Ctx(ctx).Warning("failed to calculate score", helpers.Error(err))
	}

	opap.reweightComplianceScores()

	return processErr
}

// ProcessWithStreaming processes OPA policies using streaming resource batches.
// This method is designed for large clusters where loading all resources into memory
// is prohibitive. It processes batches incrementally, keeping only the resident
// (cluster-scoped) batch in memory throughout.
//
// The streaming approach:
// 1. Receives batches via a channel (resident batch first, then namespace batches)
// 2. Keeps the resident batch in memory for the entire scan
// 3. Processes each namespace batch against the resident batch
// 4. Releases memory from namespace batches after processing
// 5. Merges results from all batches
func (opap *OPAProcessor) ProcessWithStreaming(ctx context.Context, policies *cautils.Policies, batchChan <-chan *cautils.ResourceBatch, errChan <-chan error, progressListener IJobProgressNotificationClient) error {
	ctx, span := otel.Tracer("").Start(ctx, "OPAProcessor.ProcessWithStreaming")
	defer span.End()
	opap.loggerStartScanning()
	defer opap.loggerDoneScanning()

	opap.AllPolicies = convertFrameworksToPolicies(opap.Policies, opap.ExcludedRules, cautils.GetScanningScope(opap.Metadata.ContextMetadata))
	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.AllPolicies)

	controlIDs := sortedControlIDs(policies)

	// Track the resident batch (cluster-scoped resources)
	var residentBatch *cautils.ResourceBatch
	var namespaceBatches []*cautils.ResourceBatch

	// Receive all batches first
	for batch := range batchChan {
		if batch.Scope == cautils.ClusterScope {
			residentBatch = batch
		} else {
			namespaceBatches = append(namespaceBatches, batch)
		}
	}

	// Check for errors from streaming
	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
	default:
	}

	if residentBatch == nil {
		return fmt.Errorf("no resident batch received")
	}

	// Set up session with resident resources
	opap.K8SResources = residentBatch.K8SResources
	opap.ExternalResources = residentBatch.ExternalResources
	opap.AllResources = residentBatch.AllResources

	// Build evaluation scopes from batches
	scopes := make([]evaluationScope, 0, len(namespaceBatches)+1)
	scopes = append(scopes, evaluationScope{name: residentBatch.Scope, resident: residentBatch})

	for _, batch := range namespaceBatches {
		scopes = append(scopes, evaluationScope{name: batch.Scope, batch: batch, resident: residentBatch})
	}

	if progressListener != nil {
		progressListener.Start(len(controlIDs) * len(scopes))
		defer progressListener.Stop()
	}

	remaining := make(map[string]time.Duration, len(controlIDs))
	var processErrs []error

	// Process each scope
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			processErrs = append(processErrs, err)
			break
		}

		for _, controlID := range controlIDs {
			if err := ctx.Err(); err != nil {
				processErrs = append(processErrs, err)
				break
			}
			if progressListener != nil {
				progressListener.ProgressJob(1, fmt.Sprintf("Control: %s", controlID))
			}
			if _, timedOut := opap.TimedOutControls[controlID]; timedOut {
				continue
			}

			control := policies.Controls[controlID]

			var resourcesAssociatedControl map[string]resourcesresults.ResourceAssociatedControl
			var err error

			if opap.ControlTimeout > 0 {
				budget, ok := remaining[controlID]
				if !ok {
					budget = opap.ControlTimeout
				}
				cctx, cancel := context.WithTimeout(ctx, budget)
				start := time.Now()
				resourcesAssociatedControl, err = opap.processControl(cctx, &control, scope)
				remaining[controlID] = budget - time.Since(start)
				if cctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
					opap.markControlTimedOut(&control, opap.ControlTimeout)
					opap.dropControlResults(controlID)
					err = nil
					resourcesAssociatedControl = nil
				}
				cancel()
			} else {
				resourcesAssociatedControl, err = opap.processControl(ctx, &control, scope)
			}

			if err != nil {
				processErrs = append(processErrs, fmt.Errorf("control %q: %w", control.ControlID, err))
			}

			// Update resources with latest results
			for resourceID, controlResult := range resourcesAssociatedControl {
				t, ok := opap.ResourcesResult[resourceID]
				if !ok {
					t = resourcesresults.Result{ResourceID: resourceID}
				}
				t.AssociatedControls = mergeAssociatedControls(t.AssociatedControls, controlResult, opap.AllPolicies)
				opap.ResourcesResult[resourceID] = t
			}
		}

		// Release memory from namespace batch after processing all controls
		if scope.batch != nil {
			// Clear the batch's resources to free memory
			for id := range scope.batch.AllResources {
				delete(scope.batch.AllResources, id)
			}
			for key := range scope.batch.K8SResources {
				delete(scope.batch.K8SResources, key)
			}
		}
	}

	// Rebuild scan coverage
	opap.ScanCoverage = cautils.BuildScanCoverage(opap.InfoMap, opap.ResourceToControlsMap, opap.TimedOutControls, opap.PartialGVRFailures, opap.PolicyDegradations)
	opap.ScanCoverage.ComputeCoverageScore(len(opap.Report.SummaryDetails.Controls))

	// Update results
	opap.updateResults(ctx)
	opap.markTimedOutControlsSkipped()

	scorewrapper := score.NewScoreWrapper(opap.OPASessionObj)
	if err := scorewrapper.Calculate(score.EPostureReportV2); err != nil {
		logger.L().Ctx(ctx).Warning("failed to calculate score", helpers.Error(err))
	}

	opap.reweightComplianceScores()

	return errors.Join(processErrs...)
}

// Process OPA policies (rules) on all configured controls.
//
// Resources are evaluated one scope at a time: first the resident scope
// (cluster-scoped and external objects), then one scope per namespace, each
// evaluated together with the resident scope. On clusters at or below the
// large-cluster threshold there is a single scope holding everything, so the
// evaluation input is unchanged.
//
// The scope loop is the outer loop so that a scope's resources are needed only
// while that scope is being evaluated. A resource that belongs to several
// scopes — anything resident — is therefore evaluated once per scope, and its
// per-scope verdicts are merged (see mergeAssociatedControls). This reproduces
// the accumulation the previous rule-outer/namespace-inner loop performed
// inside a single result map.
func (opap *OPAProcessor) Process(ctx context.Context, policies *cautils.Policies, progressListener IJobProgressNotificationClient) error {
	ctx, span := otel.Tracer("").Start(ctx, "OPAProcessor.Process")
	defer span.End()
	opap.loggerStartScanning()
	defer opap.loggerDoneScanning()

	scopes := opap.evaluationScopes()
	controlIDs := sortedControlIDs(policies)

	if progressListener != nil {
		progressListener.Start(len(controlIDs) * len(scopes))
		defer progressListener.Stop()
	}

	// Remaining evaluation budget per control. ControlTimeout bounds the total
	// time spent on a control, so the budget is carried across scopes instead
	// of being granted afresh to each one.
	remaining := make(map[string]time.Duration, len(controlIDs))

	var processErrs []error
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			processErrs = append(processErrs, err)
			break
		}

		for _, controlID := range controlIDs {
			if err := ctx.Err(); err != nil {
				processErrs = append(processErrs, err)
				break
			}
			if progressListener != nil {
				progressListener.ProgressJob(1, fmt.Sprintf("Control: %s", controlID))
			}
			if _, timedOut := opap.TimedOutControls[controlID]; timedOut {
				continue
			}

			control := policies.Controls[controlID]

			var resourcesAssociatedControl map[string]resourcesresults.ResourceAssociatedControl
			var err error

			if opap.ControlTimeout > 0 {
				budget, ok := remaining[controlID]
				if !ok {
					budget = opap.ControlTimeout
				}
				cctx, cancel := context.WithTimeout(ctx, budget)
				start := time.Now()
				resourcesAssociatedControl, err = opap.processControl(cctx, &control, scope)
				remaining[controlID] = budget - time.Since(start)
				if cctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
					opap.markControlTimedOut(&control, opap.ControlTimeout)
					// discard the verdicts already merged from earlier scopes:
					// a control that did not finish must contribute nothing
					opap.dropControlResults(controlID)
					err = nil
					resourcesAssociatedControl = nil
				}
				cancel()
			} else {
				resourcesAssociatedControl, err = opap.processControl(ctx, &control, scope)
			}

			if err != nil {
				processErrs = append(processErrs, fmt.Errorf("control %q: %w", control.ControlID, err))
			}

			// update resources with latest results
			for resourceID, controlResult := range resourcesAssociatedControl {
				t, ok := opap.ResourcesResult[resourceID]
				if !ok {
					t = resourcesresults.Result{ResourceID: resourceID}
				}
				t.AssociatedControls = mergeAssociatedControls(t.AssociatedControls, controlResult, opap.AllPolicies)
				opap.ResourcesResult[resourceID] = t
			}
		}
	}

	return errors.Join(processErrs...)
}

// evaluationScope is one unit of evaluation input: a batch of resources plus
// the resident batch every scope depends on.
type evaluationScope struct {
	name string
	// batch holds the scope's own resources. It is nil for the resident scope,
	// which is evaluated on its own so that cluster-scoped resources are still
	// assessed on clusters with no namespaced resources at all.
	batch    *cautils.ResourceBatch
	resident *cautils.ResourceBatch
}

// matchedObjects returns the rule's input for this scope: the scope's own
// matching objects, then the resident ones. The ordering matters because Rego
// rules see the input as an array.
//
// A namespace scope that matches nothing of its own contributes no input at
// all: evaluating it would re-run the rule on the resident objects alone,
// which the resident scope already did.
func (scope evaluationScope) matchedObjects(rule *reporthandling.PolicyRule) []workloadinterface.IMetadata {
	var objects []workloadinterface.IMetadata
	if scope.batch != nil {
		objects = getKubernetesObjects(scope.batch.K8SResources, scope.batch.AllResources, rule.Match)
		if len(objects) == 0 {
			return nil
		}
	}
	objects = append(objects, getKubernetesObjects(scope.resident.K8SResources, scope.resident.AllResources, rule.Match)...)
	objects = append(objects, getKubernetesObjectsFromExternalResources(scope.resident.ExternalResources, scope.resident.AllResources, rule.DynamicMatch)...)
	return objects
}

// evaluationScopes partitions the session's resources into the scopes to
// evaluate, resident scope first and namespaces in sorted order.
func (opap *OPAProcessor) evaluationScopes() []evaluationScope {
	resident, batches := cautils.PartitionResources(opap.K8SResources, opap.ExternalResources, opap.AllResources)

	scopes := make([]evaluationScope, 0, len(batches)+1)
	scopes = append(scopes, evaluationScope{name: resident.Scope, resident: resident})
	for _, batch := range batches {
		scopes = append(scopes, evaluationScope{name: batch.Scope, batch: batch, resident: resident})
	}

	logger.L().Debug("partitioned resources for evaluation",
		helpers.Int("scopes", len(scopes)),
		helpers.Int("residentResources", resident.Len()))

	return scopes
}

// sortedControlIDs returns the controls to evaluate in a stable order. The
// order determines how a resource's AssociatedControls are laid out, which
// used to depend on Go's map iteration order.
func sortedControlIDs(policies *cautils.Policies) []string {
	return slices.Sorted(maps.Keys(policies.Controls))
}

// dropControlResults removes every trace of a control from the results
// accumulated so far, and drops resources left with no control at all.
func (opap *OPAProcessor) dropControlResults(controlID string) {
	for resourceID, result := range opap.ResourcesResult {
		kept := make([]resourcesresults.ResourceAssociatedControl, 0, len(result.AssociatedControls))
		for _, associated := range result.AssociatedControls {
			if associated.ControlID != controlID {
				kept = append(kept, associated)
			}
		}
		if len(kept) == len(result.AssociatedControls) {
			continue
		}
		if len(kept) == 0 {
			delete(opap.ResourcesResult, resourceID)
			continue
		}
		result.AssociatedControls = kept
		opap.ResourcesResult[resourceID] = result
	}
}

func (opap *OPAProcessor) loggerStartScanning() {
	targetScan := opap.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().Start("Scanning", helpers.String(targetScan.String(), opap.clusterName))
	} else {
		logger.L().Start("Scanning " + targetScan.String())
	}
}

func (opap *OPAProcessor) loggerDoneScanning() {
	targetScan := opap.Metadata.ScanMetadata.ScanningTarget
	if reporthandlingv2.Cluster == targetScan {
		logger.L().StopSuccess("Done scanning", helpers.String(targetScan.String(), opap.clusterName))
	} else {
		logger.L().StopSuccess("Done scanning " + targetScan.String())
	}
}

// processControl processes all the rules for a given control, on a single
// scope.
//
// NOTE: the call to processControl no longer mutates the state of the current OPAProcessor instance,
// but returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processControl(ctx context.Context, control *reporthandling.Control, scope evaluationScope) (map[string]resourcesresults.ResourceAssociatedControl, error) {
	resourcesAssociatedControl := make(map[string]resourcesresults.ResourceAssociatedControl)

	var ruleErrs []error
	for i := range control.Rules {
		if err := ctx.Err(); err != nil {
			ruleErrs = append(ruleErrs, err)
			break
		}
		resourceAssociatedRule, err := opap.processRuleOnScope(ctx, &control.Rules[i], control.FixedInput, scope)
		if err != nil {
			ruleErrs = append(ruleErrs, fmt.Errorf("rule %q: %w", control.Rules[i].Name, err))
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

	return resourcesAssociatedControl, errors.Join(ruleErrs...)
}

// processRule processes a single policy rule over every scope, merging the
// per-scope verdicts exactly as Process does.
//
// Process itself does not call this: it interleaves scopes with controls so
// that a scope is visited once for all controls. processRule is the
// single-rule reference for that behaviour, and is what the parity harness
// compares the scope-outer loop against.
//
// NOTE: processRule no longer mutates the state of the current OPAProcessor instance,
// and returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processRule(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string) (map[string]*resourcesresults.ResourceAssociatedRule, error) {
	merged := make(map[string]*resourcesresults.ResourceAssociatedRule)

	var evalErrs []error
	for _, scope := range opap.evaluationScopes() {
		scoped, err := opap.processRuleOnScope(ctx, rule, fixedControlInputs, scope)
		if err != nil {
			evalErrs = append(evalErrs, err)
		}
		for resourceID, ruleResult := range scoped {
			merged[resourceID] = mergeAssociatedRule(merged[resourceID], ruleResult)
		}
	}

	return merged, errors.Join(evalErrs...)
}

// processRuleOnScope evaluates a single policy rule against a single scope,
// with some extra fixed control inputs.
func (opap *OPAProcessor) processRuleOnScope(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string, scope evaluationScope) (map[string]*resourcesresults.ResourceAssociatedRule, error) {
	resources := make(map[string]*resourcesresults.ResourceAssociatedRule)

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, fixedControlInputs)

	resourceToScan := scope.matchedObjects(rule)
	inputResources, err := reporthandling.RegoResourcesAggregator(
		rule,
		resourceToScan, // NOTE: this uses the initial snapshot of AllResources
	)
	if err != nil {
		opap.markResourcesSkipped(resources, rule, ruleRegoDependenciesData, resourceToScan, err)
		return resources, fmt.Errorf("aggregator failed for namespace %q: %w", scope.name, err)
	}

	if len(inputResources) == 0 {
		return resources, nil // no resources found for testing
	}

	inputRawResources := workloadinterface.ListMetaToMap(inputResources)

	// the failed resources are a subgroup of the enumeratedData, so we store the enumeratedData like it was the input data
	enumeratedData, err := opap.enumerateData(ctx, rule, inputRawResources)
	if err != nil {
		opap.markResourcesSkipped(resources, rule, ruleRegoDependenciesData, inputResources, err)
		return resources, fmt.Errorf("enumerator failed for namespace %q: %w", scope.name, err)
	}

	inputResources = objectsenvelopes.ListMapToMeta(enumeratedData)

	for _, inputResource := range inputResources {
		if opap.skipNamespace(inputResource.GetNamespace()) {
			continue
		}
		opap.AllResources[inputResource.GetID()] = inputResource
	}

	ruleResponses, err := opap.runOPAOnSingleRule(ctx, rule, inputRawResources, ruleData, ruleRegoDependenciesData)
	if err != nil {
		opap.markResourcesSkipped(resources, rule, ruleRegoDependenciesData, inputResources, err)
		return resources, fmt.Errorf("rego eval failed for namespace %q: %w", scope.name, err)
	}

	// Build the set of failed IDs so we can correctly mark the remainder as passed.
	// Resources are only written to the result map after a successful OPA evaluation,
	// preventing stale StatusPassed entries when evaluation fails.
	// Failed entries are pre-seeded with rule metadata so the loop below can
	// find them and attach paths/status without losing Name/ControlConfigurations.
	failedIDs := make(map[string]struct{})
	for _, ruleResponse := range ruleResponses {
		for _, failedResource := range objectsenvelopes.ListMapToMeta(ruleResponse.GetFailedResources()) {
			if opap.skipNamespace(failedResource.GetNamespace()) {
				continue
			}
			id := failedResource.GetID()
			failedIDs[id] = struct{}{}
			if _, exists := resources[id]; exists {
				continue
			}
			resources[id] = &resourcesresults.ResourceAssociatedRule{
				Name:                  rule.Name,
				ControlConfigurations: ruleRegoDependenciesData.PostureControlInputs,
			}
		}
	}
	for _, inputResource := range inputResources {
		if opap.skipNamespace(inputResource.GetNamespace()) {
			continue
		}
		id := inputResource.GetID()
		if _, failed := failedIDs[id]; failed {
			continue
		}
		if existing, ok := resources[id]; ok && (existing.Status == apis.StatusFailed || existing.Status == apis.StatusSkipped) {
			continue
		}
		resources[id] = &resourcesresults.ResourceAssociatedRule{
			Name:                  rule.Name,
			ControlConfigurations: ruleRegoDependenciesData.PostureControlInputs,
			Status:                apis.StatusPassed,
		}
	}

	// ruleResponse to ruleResult
	for _, ruleResponse := range ruleResponses {
		failedResources := objectsenvelopes.ListMapToMeta(ruleResponse.GetFailedResources())
		for _, failedResource := range failedResources {
			if opap.skipNamespace(failedResource.GetNamespace()) {
				continue
			}
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
				relatedResourcesSet := mapset.NewSet[string](ruleResult.RelatedResourcesIDs...)
				for _, relatedObject := range ruleResponse.RelatedObjects {
					wl := objectsenvelopes.NewObject(relatedObject.Object)
					if wl != nil {
						if !relatedResourcesSet.Contains(wl.GetID()) {
							ruleResult.RelatedResourcesIDs = append(ruleResult.RelatedResourcesIDs, wl.GetID())
						}
						relatedResourcesSet.Add(wl.GetID())
						ruleResult.Paths = appendPaths(ruleResult.Paths, relatedObject.AssistedRemediation, wl.GetID())
					}
				}
			}

			resources[failedResource.GetID()] = ruleResult
		}
	}
	return resources, nil
}

// markResourcesSkipped seeds the result map with StatusSkipped entries for every
// in-scope input resource and records the OPA error in opap.InfoMap. Without
// this, an evaluation failure would leave the resources absent from the rule's
// output: a sibling rule that passed could then drive the parent control to
// StatusPassed, masking the fact that this rule never completed.
func (opap *OPAProcessor) markResourcesSkipped(out map[string]*resourcesresults.ResourceAssociatedRule, rule *reporthandling.PolicyRule, deps resources.RegoDependenciesData, inputResources []workloadinterface.IMetadata, evalErr error) {
	statusInfo := apis.StatusInfo{
		InnerInfo:   evalErr.Error(),
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusUnknown,
	}
	for _, inputResource := range inputResources {
		if opap.skipNamespace(inputResource.GetNamespace()) {
			continue
		}
		id := inputResource.GetID()
		if existing, ok := out[id]; ok && existing.Status == apis.StatusFailed {
			continue // don't downgrade a definitive failure to skipped
		}
		out[id] = &resourcesresults.ResourceAssociatedRule{
			Name:                  rule.Name,
			ControlConfigurations: deps.PostureControlInputs,
			Status:                apis.StatusSkipped,
			SubStatus:             apis.SubStatusUnknown,
		}
		if opap.InfoMap != nil {
			opap.InfoMap[id] = statusInfo
		}
	}
}

func (opap *OPAProcessor) markTimedOutControlsSkipped() {
	if len(opap.TimedOutControls) == 0 {
		return
	}
	status := &apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusNotEvaluated,
	}
	for controlID := range opap.TimedOutControls {
		if ctrl, ok := opap.Report.SummaryDetails.Controls[controlID]; ok {
			ctrl.SetStatus(status)
			opap.Report.SummaryDetails.Controls[controlID] = ctrl
		}
		for i := range opap.Report.SummaryDetails.Frameworks {
			if ctrl, ok := opap.Report.SummaryDetails.Frameworks[i].Controls[controlID]; ok {
				ctrl.SetStatus(status)
				opap.Report.SummaryDetails.Frameworks[i].Controls[controlID] = ctrl
			}
		}
	}
}

func (opap *OPAProcessor) reweightComplianceScores() {
	if len(opap.TimedOutControls) == 0 {
		return
	}
	var sum float32
	var count int
	for ctrlID := range opap.Report.SummaryDetails.Controls {
		if _, ok := opap.TimedOutControls[ctrlID]; !ok {
			ctrl := opap.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ctrlID)
			sum += ctrl.GetComplianceScore()
		}
		count++
	}
	if count > 0 {
		opap.Report.SummaryDetails.ComplianceScore = sum / float32(count)
	} else {
		opap.Report.SummaryDetails.ComplianceScore = 0
	}
	for i := range opap.Report.SummaryDetails.Frameworks {
		var fsum float32
		var fcount int
		for ctrlID := range opap.Report.SummaryDetails.Frameworks[i].Controls {
			if _, ok := opap.TimedOutControls[ctrlID]; !ok {
				ctrl := opap.Report.SummaryDetails.Frameworks[i].Controls.GetControl(reportsummary.EControlCriteriaID, ctrlID)
				fsum += ctrl.GetComplianceScore()
			}
			fcount++
		}
		if fcount > 0 {
			opap.Report.SummaryDetails.Frameworks[i].ComplianceScore = fsum / float32(fcount)
		} else {
			opap.Report.SummaryDetails.Frameworks[i].ComplianceScore = 0
		}
	}
}

// markControlTimedOut records in opap.TimedOutControls that a control's
// evaluation was aborted after exceeding ControlTimeout, so it surfaces as a
// not-evaluated control instead of silently stalling the scan.
func (opap *OPAProcessor) markControlTimedOut(control *reporthandling.Control, timeout time.Duration) {
	if opap.TimedOutControls == nil {
		opap.TimedOutControls = make(map[string]string)
	}
	opap.TimedOutControls[control.ControlID] = fmt.Sprintf("control evaluation timed out after %s", timeout)
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

func (opap *OPAProcessor) runOPAOnSingleRule(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		return opap.runRegoOnK8s(ctx, rule, k8sObjects, getRuleData, ruleRegoDependenciesData)
	case reporthandling.CELLanguage:
		return opap.runCELOnK8s(ctx, rule, k8sObjects, getRuleData)
	default:
		return nil, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

// runCELOnK8s evaluates a CEL-based PolicyRule against k8s objects.
// Stub: the CEL evaluator is added in follow-up PRs (kubescape/kubescape#2001).
func (opap *OPAProcessor) runCELOnK8s(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, getRuleData func(*reporthandling.PolicyRule) string) ([]reporthandling.RuleResponse, error) {
	return nil, fmt.Errorf("rule: '%s', CEL evaluation not yet implemented", rule.Name)
}

// runRegoOnK8s compiles an OPA PolicyRule and evaluates its against k8s
func (opap *OPAProcessor) runRegoOnK8s(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	opap.opaRegisterOnce.Do(func() {
		rego.RegisterBuiltin2(cosignVerifySignatureDeclaration, cosignVerifySignatureDefinition)
		rego.RegisterBuiltin1(cosignHasSignatureDeclaration, cosignHasSignatureDefinition)
		rego.RegisterBuiltin1(imageNameNormalizeDeclaration, imageNameNormalizeDefinition)
	})

	ruleData := getRuleData(rule)
	compiled, err := opap.getCompiledRule(ctx, rule.Name, ruleData, opap.printEnabled)
	if err != nil {
		return nil, fmt.Errorf("rule: '%s', %w", rule.Name, err)
	}

	store, err := ruleRegoDependenciesData.TOStorage()
	if err != nil {
		return nil, err
	}

	results, err := opap.regoEval(ctx, k8sObjects, compiled, &store)
	if err != nil {
		return nil, fmt.Errorf("rule '%s': rego eval failed: %w", rule.Name, err)
	}

	return results, nil
}

func (opap *OPAProcessor) Print(ctx opaprint.Context, str string) error {
	msg := fmt.Sprintf("opa-print: {%v} - %s", ctx.Location, str)
	logger.L().Ctx(ctx.Context).Debug(msg)
	return nil
}

func (opap *OPAProcessor) regoEval(ctx context.Context, inputObj []map[string]any, compiledRego *ast.Compiler, store *storage.Store) ([]reporthandling.RuleResponse, error) {
	rego := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(*store),
		rego.EnablePrintStatements(opap.printEnabled),
		rego.PrintHook(opap),
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

func (opap *OPAProcessor) enumerateData(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any) ([]map[string]any, error) {
	if ruleEnumeratorData(rule) == "" {
		return k8sObjects, nil
	}

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, nil)
	ruleResponse, err := opap.runOPAOnSingleRule(ctx, rule, k8sObjects, ruleEnumeratorData, ruleRegoDependenciesData)
	if err != nil {
		return nil, err
	}

	failedResources := make([]map[string]any, 0, len(ruleResponse))
	for _, ruleResponse := range ruleResponse {
		failedResources = append(failedResources, ruleResponse.GetFailedResources()...)
	}

	return failedResources, nil
}

// makeRegoDeps builds a resources.RegoDependenciesData struct for the current cloud provider.
//
// If some extra fixedControlInputs are provided, they are merged into the "posture" control inputs.
func (opap *OPAProcessor) makeRegoDeps(configInputs []reporthandling.ControlConfigInputs, fixedControlInputs map[string][]string) resources.RegoDependenciesData {
	postureControlInputs := opap.regoDependenciesData.GetFilteredPostureControlConfigInputs(configInputs)

	clonedPostureInputs := make(map[string][]string, len(postureControlInputs)+len(fixedControlInputs))

	for k, v := range postureControlInputs {
		clonedPostureInputs[k] = slices.Clone(v)
	}

	for k, v := range fixedControlInputs {
		clonedPostureInputs[k] = slices.Clone(v)
	}

	dataControlInputs := map[string]string{
		"cloudProvider": opap.Report.ClusterCloudProvider,
	}

	return resources.RegoDependenciesData{
		DataControlInputs:    dataControlInputs,
		PostureControlInputs: clonedPostureInputs,
	}
}

func (opap *OPAProcessor) skipNamespace(ns string) bool {
	if ns == "" {
		// Cluster-scoped resources are never filtered by namespace selectors.
		return false
	}

	if includeNamespaces := opap.includeNamespaces; len(includeNamespaces) > 0 {
		if !slices.Contains(includeNamespaces, ns) {
			// skip ns not in IncludeNamespaces
			return true
		}
	} else if excludeNamespaces := opap.excludeNamespaces; len(excludeNamespaces) > 0 {
		if slices.Contains(excludeNamespaces, ns) {
			// skip ns in ExcludeNamespaces
			return true
		}
	}
	return false
}

func split(namespaces string) []string {
	parts := strings.Split(namespaces, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

func (opap *OPAProcessor) getCompiledRule(ctx context.Context, ruleName, ruleData string, printEnabled bool) (*ast.Compiler, error) {
	cacheKey := ruleName + "|" + ruleData

	opap.compiledMu.RLock()
	if compiled, ok := opap.compiledModules[cacheKey]; ok {
		opap.compiledMu.RUnlock()
		return compiled, nil
	}
	opap.compiledMu.RUnlock()

	opap.compiledMu.Lock()
	defer opap.compiledMu.Unlock()

	if compiled, ok := opap.compiledModules[cacheKey]; ok {
		return compiled, nil
	}

	baseModules, err := getRuleDependencies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule dependencies: %w", err)
	}

	modules := make(map[string]string, len(baseModules)+1)
	maps.Copy(modules, baseModules)
	modules[ruleName] = ruleData

	compiled, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: printEnabled,
		ParserOptions:         ast.ParserOptions{RegoVersion: ast.RegoV0},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to compile rule '%s': %w", ruleName, err)
	}

	opap.compiledModules[cacheKey] = compiled
	return compiled, nil
}
