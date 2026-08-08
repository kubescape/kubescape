package opaprocessor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"runtime"
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
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor/cel"
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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
)

const ScoreConfigPath = "/resources/config"

type IJobProgressNotificationClient interface {
	Start(allSteps int)
	ProgressJob(step int, message string)
	Stop()
}

// compiledRule pairs a compiled rule with the Rego version it was actually
// compiled under, so evaluation (regoEval) can be run at the matching
// version rather than assuming RegoV1.
type compiledRule struct {
	compiler *ast.Compiler
	version  ast.RegoVersion
}

// OPAProcessor processes Open Policy Agent rules.
type OPAProcessor struct {
	clusterName          string
	regoDependenciesData *resources.RegoDependenciesData
	*cautils.OPASessionObj
	exceptionEventRecorder record.EventRecorder
	excludeNamespaces      []string
	includeNamespaces      []string
	printEnabled           bool
	compiledModules        map[string]compiledRule
	compiledMu             sync.RWMutex
	mu                     sync.Mutex
	// ControlTimeout, when non-zero, bounds the evaluation time of a single
	// control. If exceeded, the control is recorded as not evaluated instead
	// of stalling or aborting the whole scan.
	ControlTimeout time.Duration
	// TimedOutControls maps controlID to the reason its evaluation was
	// aborted after exceeding ControlTimeout.
	TimedOutControls map[string]string
	// celEvaluator is the CEL engine shared across the whole scan, built once
	// via celEvaluatorOnce. One evaluator (and its compiled-program cache) is
	// reused for every control and object because building the CEL env is far
	// more expensive than evaluating with it.
	celEvaluator     *cel.Evaluator
	celEvaluatorOnce sync.Once
	celEvaluatorErr  error
	// celNamespaceIndex maps namespace name -> the scan's Namespace object, so
	// CEL evaluation can bind namespaceObject the way the apiserver does. In the
	// non-streaming path it is built at construction (see indexNamespaces), where
	// AllResources is already fully collected, so the snapshot is structurally
	// independent of whatever rules write into AllResources mid-scan instead of
	// depending on when the first CEL rule happens to run. The streaming path has
	// no such snapshot to take, so it extends the index batch by batch via
	// indexNamespacesFrom, always before the batch is evaluated.
	celNamespaceIndex map[string]map[string]any
	// initialResourceCount is the size of AllResources snapshotted once at
	// construction, so the large-cluster namespace-bucketing decision (see
	// getNamespaceName) is made once per scan instead of drifting mid-scan as
	// rules write aggregator-produced resources back into AllResources.
	initialResourceCount int
}

// NewOPAProcessor snapshots len(sessionObj.AllResources) at construction for
// the large-cluster bucketing decision. In the non-streaming path AllResources
// must therefore already be fully collected (CollectResources must have run).
// The streaming path populates AllResources asynchronously, so it calls
// SetInitialResourceCount with the pre-scan cluster-size estimate instead.
func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData, clusterName string, excludeNamespaces string, includeNamespaces string, enableRegoPrint bool, exceptionEventRecorder record.EventRecorder) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
		regoDependenciesData.DataControlInputs = sessionObj.RegoInputData.DataControlInputs
	}

	initialResourceCount := 0
	if sessionObj != nil {
		initialResourceCount = len(sessionObj.AllResources)
	}

	return &OPAProcessor{
		OPASessionObj:          sessionObj,
		regoDependenciesData:   regoDependenciesData,
		clusterName:            clusterName,
		exceptionEventRecorder: exceptionEventRecorder,
		excludeNamespaces:      split(excludeNamespaces),
		includeNamespaces:      split(includeNamespaces),
		printEnabled:           enableRegoPrint,
		compiledModules:        make(map[string]compiledRule),
		TimedOutControls:       make(map[string]string),
		initialResourceCount:   initialResourceCount,
		celNamespaceIndex:      indexNamespaces(sessionObj),
	}
}

// indexNamespaces maps namespace name -> Namespace object out of the session's
// collected resources, for the CEL namespaceObject binding (see
// celNamespaceObjectFor). Nil-safe by returning an empty index: a nil session
// or a scan that never collected Namespaces (file scans, frameworks with no
// Namespace-matching control) just resolves every lookup to nil.
//
// In the streaming path AllResources is still empty here, so this yields an
// empty index and ProcessWithStreaming fills it in per batch via
// indexNamespacesFrom instead.
func indexNamespaces(sessionObj *cautils.OPASessionObj) map[string]map[string]any {
	if sessionObj == nil {
		return nil
	}
	index := make(map[string]map[string]any)
	addNamespacesToIndex(index, sessionObj.AllResources)
	return index
}

// indexNamespacesFrom merges the Namespace objects in resources into the CEL
// namespace index. The streaming path calls it for every batch before the batch
// is evaluated, because AllResources is empty at construction time: a Namespace
// object is scoped to its own name by cautils.ResourceScope, so it arrives in
// that namespace's batch alongside the resources it contains, which is exactly
// the batch whose objects need it bound. Without this, celNamespaceObjectFor
// would resolve every namespace to nil under --enable-streaming and
// admission-scoped CEL rules would diverge from the non-streaming path.
func (opap *OPAProcessor) indexNamespacesFrom(resources map[string]workloadinterface.IMetadata) {
	if len(resources) == 0 {
		return
	}
	if opap.celNamespaceIndex == nil {
		opap.celNamespaceIndex = make(map[string]map[string]any)
	}
	addNamespacesToIndex(opap.celNamespaceIndex, resources)
}

// addNamespacesToIndex indexes every v1 Namespace object in resources by name.
func addNamespacesToIndex(index map[string]map[string]any, resources map[string]workloadinterface.IMetadata) {
	for _, resource := range resources {
		if resource == nil || resource.GetKind() != "Namespace" || resource.GetApiVersion() != "v1" {
			continue
		}
		index[resource.GetName()] = resource.GetObject()
	}
}

// SetInitialResourceCount overrides the frozen resource count used for the
// large-cluster namespace-bucketing decision (see initialResourceCount). The
// streaming path sets it to the pre-scan cluster-size estimate because
// sessionObj.AllResources is populated asynchronously by the producer goroutine
// after construction, so the snapshot taken in NewOPAProcessor would otherwise
// be 0 and evaluationScopes() would never partition.
func (opap *OPAProcessor) SetInitialResourceCount(count int) {
	opap.initialResourceCount = count
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
// It processes batches incrementally, keeping the resident (cluster-scoped)
// batch in memory throughout.
//
// The streaming approach:
//  1. Receives batches via a channel (resident batch first, then namespace batches)
//  2. Keeps the resident batch in memory for the entire scan
//  3. Processes each namespace batch against the resident batch as it arrives
//  4. Merges each namespace batch's resources into the session-wide maps so
//     downstream stages (exceptions, printers, image scanning) can access them
//  5. Merges results from all batches
//
// Note: Streaming bounds the OPA evaluation input (resident batch plus one
// namespace batch at a time), not total memory: the producer holds the whole
// cluster while collecting, and this method retains every resource in
// AllResources for downstream stages.
func (opap *OPAProcessor) ProcessWithStreaming(ctx context.Context, batchChan <-chan *cautils.ResourceBatch, errChan <-chan error, progressListener IJobProgressNotificationClient, expectedNamespaceBatches int) error {
	ctx, span := otel.Tracer("").Start(ctx, "OPAProcessor.ProcessWithStreaming")
	defer span.End()
	opap.loggerStartScanning()
	defer opap.loggerDoneScanning()

	opap.AllPolicies = convertFrameworksToPolicies(opap.Policies, opap.ExcludedRules, cautils.GetScanningScope(opap.Metadata.ContextMetadata))
	ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, opap.Policies, opap.AllPolicies)

	controlIDs := sortedControlIDs(opap.AllPolicies)

	// Calculate total progress steps: controls × (resident scope + namespace scopes)
	totalSteps := len(controlIDs) * (1 + expectedNamespaceBatches)
	if progressListener != nil {
		progressListener.Start(totalSteps)
		defer progressListener.Stop()
	}

	// Track the resident batch (cluster-scoped resources)
	var residentBatch *cautils.ResourceBatch

	// First, wait for the resident batch
	for {
		select {
		case batch, ok := <-batchChan:
			if !ok {
				// Channel closed without sending a batch.
				// Check if the producer left an error.
				select {
				case err, ok := <-errChan:
					if ok && err != nil {
						return fmt.Errorf("batch channel closed without resident batch: %w", err)
					}
					// errChan closed without error — no resident batch was ever sent.
					return fmt.Errorf("batch channel closed without resident batch")
				default:
					return fmt.Errorf("batch channel closed without resident batch")
				}
			}
			if batch.Scope == cautils.ClusterScope {
				residentBatch = batch
			} else {
				// First batch must be resident
				return fmt.Errorf("first batch must be resident (cluster-scoped), got: %s", batch.Scope)
			}
			goto haveResident
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
haveResident:

	if residentBatch == nil {
		return fmt.Errorf("no resident batch received")
	}

	// Set up session with resident resources
	// Initialize AllResources with resident resources, we'll merge namespace resources as we process them
	opap.K8SResources = make(cautils.K8SResources)
	for k, v := range residentBatch.K8SResources {
		opap.K8SResources[k] = v
	}
	opap.ExternalResources = residentBatch.ExternalResources
	opap.AllResources = make(map[string]workloadinterface.IMetadata)
	for k, v := range residentBatch.AllResources {
		opap.AllResources[k] = v
	}

	// Index any Namespace objects the resident batch carries before evaluating,
	// so CEL's namespaceObject binding is populated for this scope's objects.
	opap.indexNamespacesFrom(residentBatch.AllResources)

	// Process resident batch first
	residentScope := evaluationScope{name: residentBatch.Scope, resident: residentBatch}
	if err := opap.processScope(ctx, opap.AllPolicies, controlIDs, residentScope, progressListener); err != nil {
		return err
	}

	// Process namespace batches as they arrive
	for {
		select {
		case batch, ok := <-batchChan:
			if !ok {
				// Channel closed, no more batches
				goto done
			}
			if batch.Scope == cautils.ClusterScope {
				return fmt.Errorf("received duplicate resident batch")
			}

			// A namespace's own Namespace object is scoped to this batch, so
			// index it before evaluating the batch that needs it bound.
			opap.indexNamespacesFrom(batch.AllResources)

			// Process this namespace batch
			namespaceScope := evaluationScope{name: batch.Scope, batch: batch, resident: residentBatch}
			if err := opap.processScope(ctx, opap.AllPolicies, controlIDs, namespaceScope, progressListener); err != nil {
				return err
			}

			// Merge namespace batch resources into the session-wide map so
			// downstream stages (exception matching, printers, image scanning,
			// prioritisation) can access them.
			for resourceID, resource := range batch.AllResources {
				opap.AllResources[resourceID] = resource
			}
			for gvr, ids := range batch.K8SResources {
				opap.K8SResources[gvr] = append(opap.K8SResources[gvr], ids...)
			}

		case err, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

done:
	// Drain any remaining error (non-blocking; errChan may already be closed).
	select {
	case err, ok := <-errChan:
		if ok && err != nil {
			return err
		}
	default:
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

	return nil
}

// processScope processes all controls for a single evaluation scope.
// Each scope gets the full ControlTimeout budget — the timeout is not shared
// across scopes, so a control that completes in earlier scopes keeps its
// accumulated results even if a later scope exceeds the budget.
func (opap *OPAProcessor) processScope(ctx context.Context, policies *cautils.Policies, controlIDs []string, scope evaluationScope, progressListener IJobProgressNotificationClient) error {
	var processErrs []error
	var processErrsMu sync.Mutex

	numWorkers := runtime.GOMAXPROCS(0)
	controlChan := make(chan string, len(controlIDs))
	for _, id := range controlIDs {
		controlChan <- id
	}
	close(controlChan)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for controlID := range controlChan {
				if err := ctx.Err(); err != nil {
					processErrsMu.Lock()
					processErrs = append(processErrs, err)
					processErrsMu.Unlock()
					return // exit worker early on context cancellation
				}

				if progressListener != nil {
					opap.mu.Lock()
					progressListener.ProgressJob(1, fmt.Sprintf("Control: %s", controlID))
					opap.mu.Unlock()
				}

				opap.mu.Lock()
				_, timedOut := opap.TimedOutControls[controlID]
				opap.mu.Unlock()
				if timedOut {
					continue
				}

				control := policies.Controls[controlID]

				var resourcesAssociatedControl map[string]resourcesresults.ResourceAssociatedControl
				var err error

				if opap.ControlTimeout > 0 {
					cctx, cancel := context.WithTimeout(ctx, opap.ControlTimeout)
					resourcesAssociatedControl, err = opap.processControl(cctx, &control, scope)
					if cctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
						opap.markControlTimedOut(&control, opap.ControlTimeout)
						// Keep results accumulated from earlier scopes; only discard
						// the current scope's verdicts since the control did not finish.
						err = nil
						resourcesAssociatedControl = nil
					}
					cancel()
				} else {
					resourcesAssociatedControl, err = opap.processControl(ctx, &control, scope)
				}

				if err != nil {
					processErrsMu.Lock()
					processErrs = append(processErrs, fmt.Errorf("control %q: %w", control.ControlID, err))
					processErrsMu.Unlock()
				}

				// Update resources with latest results
				if len(resourcesAssociatedControl) > 0 {
					opap.mu.Lock()
					for resourceID, controlResult := range resourcesAssociatedControl {
						t, ok := opap.ResourcesResult[resourceID]
						if !ok {
							t = resourcesresults.Result{ResourceID: resourceID}
						}
						t.AssociatedControls = mergeAssociatedControls(t.AssociatedControls, controlResult, opap.AllPolicies)
						opap.ResourcesResult[resourceID] = t
					}
					opap.mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

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

	// Delegate to processScope so the timeout and evaluation logic lives in
	// one place instead of two near-identical loops that have already drifted.
	var processErrs []error
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			processErrs = append(processErrs, err)
			break
		}
		if err := opap.processScope(ctx, policies, controlIDs, scope, progressListener); err != nil {
			processErrs = append(processErrs, err)
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
// evaluate, resident scope first and namespaces in sorted order. The
// large-cluster bucketing decision is made from initialResourceCount — the
// count frozen at construction — rather than the live size of AllResources,
// so aggregator write-back during evaluation cannot re-bucket namespaces
// mid-scan.
func (opap *OPAProcessor) evaluationScopes() []evaluationScope {
	resident, batches := cautils.PartitionResources(opap.initialResourceCount, opap.K8SResources, opap.ExternalResources, opap.AllResources)

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

type policyControl struct {
	key     string
	control reporthandling.Control
}

// sortedControlIDs returns the keys of the controls to evaluate in a stable
// order. The order determines how a resource's AssociatedControls are laid out,
// which used to depend on Go's map iteration order. Keys (rather than
// ControlIDs) are returned because the scope loops look controls back up in
// policies.Controls, which is keyed by name, and because a control with an
// empty ControlID must still be addressable.
func sortedControlIDs(policies *cautils.Policies) []string {
	items := sortedPolicyControls(policies.Controls)
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.key)
	}
	return keys
}

// sortedPolicyControls orders controls by ControlID, falling back to the map
// key for controls that have no ControlID, and breaks ties on the key so the
// order is total. Sorting on ControlID rather than the map key keeps the
// evaluation order aligned with the user-visible control identity.
func sortedPolicyControls(controls map[string]reporthandling.Control) []policyControl {
	out := make([]policyControl, 0, len(controls))
	for key, control := range controls {
		out = append(out, policyControl{key: key, control: control})
	}
	slices.SortFunc(out, func(a, b policyControl) int {
		if c := strings.Compare(policyControlSortKey(a), policyControlSortKey(b)); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	return out
}

func policyControlSortKey(item policyControl) string {
	if item.control.ControlID != "" {
		return item.control.ControlID
	}
	return item.key
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
		resourceAssociatedRule, err := opap.processRule(ctx, &control.Rules[i], control.FixedInput, scope, control.ControlID)
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

// processRule processes a single policy rule. When scope is provided
// (scope.name != ""), it evaluates the rule against that scope only. When
// scope is empty, it loops over every scope — this is the path used by the
// parity harness; Process and ProcessWithStreaming always pass a concrete
// scope.
//
// controlID is threaded to enumerateData and runOPAOnSingleRule for CEL
// policy support (VAP binding lookups).
//
// NOTE: processRule no longer mutates the state of the current OPAProcessor instance,
// and returns a map instead, to be merged by the caller.
func (opap *OPAProcessor) processRule(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string, scope evaluationScope, controlID string) (map[string]*resourcesresults.ResourceAssociatedRule, error) {
	if scope.name != "" {
		return opap.processRuleOnScope(ctx, rule, fixedControlInputs, scope, controlID)
	}

	// No explicit scope — loop over all scopes (parity harness path).
	merged := make(map[string]*resourcesresults.ResourceAssociatedRule)
	var evalErrs []error
	for _, s := range opap.evaluationScopes() {
		scoped, err := opap.processRuleOnScope(ctx, rule, fixedControlInputs, s, controlID)
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
func (opap *OPAProcessor) processRuleOnScope(ctx context.Context, rule *reporthandling.PolicyRule, fixedControlInputs map[string][]string, scope evaluationScope, controlID string) (map[string]*resourcesresults.ResourceAssociatedRule, error) {
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
	enumeratedData, err := opap.enumerateData(ctx, rule, inputRawResources, controlID)
	if err != nil {
		opap.markResourcesSkipped(resources, rule, ruleRegoDependenciesData, inputResources, err)
		return resources, fmt.Errorf("enumerator failed for namespace %q: %w", scope.name, err)
	}

	inputResources = objectsenvelopes.ListMapToMeta(enumeratedData)

	var addedResources []workloadinterface.IMetadata
	for _, inputResource := range inputResources {
		if opap.skipNamespace(inputResource.GetNamespace()) {
			continue
		}
		addedResources = append(addedResources, inputResource)
	}

	if len(addedResources) > 0 {
		opap.mu.Lock()
		for _, inputResource := range addedResources {
			// AllResources is also the partitioning input (evaluationScopes →
			// PartitionResources), so this aggregator write-back grows the map
			// mid-scan. Bucketing must keep using the frozen initialResourceCount,
			// not the live length, or later rules could see per-namespace scopes.
			opap.AllResources[inputResource.GetID()] = inputResource
		}
		opap.mu.Unlock()
	}

	ruleResponses, celOut, err := opap.runOPAOnSingleRule(ctx, rule, inputRawResources, ruleData, ruleRegoDependenciesData, controlID)
	if err != nil {
		opap.markResourcesSkipped(resources, rule, ruleRegoDependenciesData, inputResources, err)
		return resources, fmt.Errorf("rego eval failed for namespace %q: %w", scope.name, err)
	}

	// Record CEL resources with unknown verdicts as skipped before pass-inference.
	opap.seedCELSkips(resources, rule, ruleRegoDependenciesData, celOut.skipped)

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
		if _, excluded := celOut.excluded[id]; excluded {
			continue // outside the CEL policy's scope: not evaluated, so not a pass
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
			opap.mu.Lock()
			opap.InfoMap[id] = statusInfo
			opap.mu.Unlock()
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
	opap.mu.Lock()
	defer opap.mu.Unlock()
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

func (opap *OPAProcessor) runOPAOnSingleRule(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData, controlID string) ([]reporthandling.RuleResponse, celOutcome, error) {
	switch rule.RuleLanguage {
	case reporthandling.RegoLanguage, reporthandling.RegoLanguage2:
		responses, err := opap.runRegoOnK8s(ctx, rule, k8sObjects, getRuleData, ruleRegoDependenciesData)
		return responses, celOutcome{}, err
	case reporthandling.CELLanguage:
		return opap.runCELOnK8s(ctx, rule, k8sObjects, getRuleData, controlID)
	default:
		return nil, celOutcome{}, fmt.Errorf("rule: '%s', language '%v' not supported", rule.Name, rule.RuleLanguage)
	}
}

// celOutcome carries the per-resource results of a CEL rule that are not
// violations: resources whose verdict is unknown (skipped) and resources the
// policy does not cover (excluded). processRule applies these so neither kind is
// misreported as passed. The Rego path returns a zero celOutcome.
type celOutcome struct {
	// skipped holds resources with an unknown verdict (a validation errored on
	// them): they must land as StatusSkipped, not passed.
	skipped []skippedCELResource
	// excluded holds the IDs of resources outside the policy's matchConstraints:
	// admission would never match them, so they must not appear in the rule's
	// results at all.
	excluded map[string]struct{}
}

type skippedCELResource struct {
	obj map[string]any
	err error
}

// runCELOnK8s evaluates a CEL-based PolicyRule against k8s objects by loading
// the control's ValidatingAdmissionPolicy from the embedded bundle and running
// its validations. controlID is threaded down from processControl (not read off
// the rule) and selects which policy to load.
//
// getRuleData is part of the shared dispatch signature but unused here: CEL
// expressions come from the loaded VAP, not from the rule's Rego text.
//
// Verdicts map to the Rego path's shape (processRule infers the passing
// resources as the input minus everything else), but per resource rather than
// per batch, so one odd object cannot bury the rest:
//   - a violation produces a RuleResponse (a failure);
//   - an object outside the policy's matchConstraints is excluded, matching
//     admission where it is never matched;
//   - an object with no violation but an eval error has an unknown verdict and
//     is skipped, never inferred as a pass;
//   - anything else passes (no entry; processRule infers it).
//
// A control-wide failure (the evaluator or policy will not load) is the only
// rule-level error: every object hits it identically, so the whole rule is
// skipped, the same path a Rego eval error takes.
func (opap *OPAProcessor) runCELOnK8s(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, _ func(*reporthandling.PolicyRule) string, controlID string) ([]reporthandling.RuleResponse, celOutcome, error) {
	evaluator, err := opap.getCELEvaluator()
	if err != nil {
		return nil, celOutcome{}, fmt.Errorf("rule: '%s', %w", rule.Name, err)
	}

	var responses []reporthandling.RuleResponse
	outcome := celOutcome{excluded: make(map[string]struct{})}
	for _, obj := range k8sObjects {
		if err := ctx.Err(); err != nil {
			return nil, celOutcome{}, err
		}

		// namespaceObject is the resource's Namespace object when the scan
		// collected it, and nil otherwise — the evaluator then binds null, so a
		// policy reading namespaceObject.* sees an absent namespace (and a
		// selection into it eval-errors and skips, never passes). File scans and
		// scans whose frameworks never matched Namespaces stay on that safe path.
		eval, err := evaluator.EvaluateControl(ctx, controlID, obj, opap.celNamespaceObjectFor(obj))
		if err != nil {
			return nil, celOutcome{}, fmt.Errorf("rule: '%s', %w", rule.Name, err)
		}

		if !eval.Applicable {
			// Exclusions are silent in the results (the resource is out of scope,
			// as at admission), but log one so a wrong GVR guess that quietly drops
			// a resource the control should have seen stays diagnosable.
			resID := celResourceID(obj)
			logger.L().Debug("CEL control does not apply to resource, excluding it",
				helpers.String("rule", rule.Name),
				helpers.String("resource", resID))
			outcome.excluded[resID] = struct{}{}
			continue
		}

		violated := false
		var messages []string
		var hints []cel.PathHint
		var objErrs []error
		for _, res := range eval.Results {
			if res.Err != nil {
				objErrs = append(objErrs, res.Err)
				continue
			}
			if !res.Passed {
				violated = true
				messages = append(messages, res.Message)
				hints = append(hints, res.Paths...)
			}
		}

		switch {
		case violated:
			responses = append(responses, celRuleResponse(rule, obj, messages, hints))
			// A confirmed violation wins over a sibling validation that errored,
			// matching admission (a deny stands). Surface the dropped errors so a
			// broken validation in an otherwise-failing policy is not invisible.
			if len(objErrs) > 0 {
				logger.L().Debug("CEL validation error on an already-violating resource",
					helpers.String("rule", rule.Name),
					helpers.String("resource", celResourceID(obj)),
					helpers.Error(errors.Join(objErrs...)))
			}
		case len(objErrs) > 0:
			outcome.skipped = append(outcome.skipped, skippedCELResource{obj: obj, err: errors.Join(objErrs...)})
		}
	}

	return responses, outcome, nil
}

// seedCELSkips records the CEL rule's unknown-verdict resources as StatusSkipped
// (with their eval error in InfoMap) before pass-inference, so they are not
// later mistaken for passes. It mirrors markResourcesSkipped but per resource,
// each with its own error, and never downgrades a confirmed failure.
func (opap *OPAProcessor) seedCELSkips(out map[string]*resourcesresults.ResourceAssociatedRule, rule *reporthandling.PolicyRule, deps resources.RegoDependenciesData, skipped []skippedCELResource) {
	for _, s := range skipped {
		meta := objectsenvelopes.NewObject(s.obj)
		if meta == nil {
			continue
		}
		if opap.skipNamespace(meta.GetNamespace()) {
			continue
		}
		id := meta.GetID()
		if existing, ok := out[id]; ok && existing.Status == apis.StatusFailed {
			continue
		}
		out[id] = &resourcesresults.ResourceAssociatedRule{
			Name:                  rule.Name,
			ControlConfigurations: deps.PostureControlInputs,
			Status:                apis.StatusSkipped,
			SubStatus:             apis.SubStatusUnknown,
		}
		if opap.InfoMap != nil {
			opap.mu.Lock()
			opap.InfoMap[id] = apis.StatusInfo{
				InnerInfo:   s.err.Error(),
				InnerStatus: apis.StatusSkipped,
				SubStatus:   apis.SubStatusUnknown,
			}
			opap.mu.Unlock()
		}
	}
}

// getCELEvaluator lazily builds the CEL evaluator shared across the whole scan
// (see the celEvaluator field).
func (opap *OPAProcessor) getCELEvaluator() (*cel.Evaluator, error) {
	opap.celEvaluatorOnce.Do(func() {
		opap.celEvaluator, opap.celEvaluatorErr = cel.NewEvaluator()
	})
	return opap.celEvaluator, opap.celEvaluatorErr
}

// celNamespaceObjectFor resolves the Namespace object a scanned resource lives
// in, for the evaluator's namespaceObject binding. It returns nil for a
// cluster-scoped resource (no namespace to resolve) and for a namespace the
// scan did not collect; the evaluator binds null in both cases, exactly as the
// apiserver binds null for cluster-scoped resources. The namespaced test is
// the same one stub.go's isNamespaced applies to the same object a moment
// later: a non-empty metadata.namespace.
func (opap *OPAProcessor) celNamespaceObjectFor(obj map[string]any) map[string]any {
	namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
	if namespace == "" {
		return nil
	}
	return opap.celNamespaceIndex[namespace]
}

// celRuleResponse builds the RuleResponse for one object that violated a CEL
// policy, shaped like the Rego path's failure responses so downstream result
// handling (processRule) treats CEL and Rego violations identically: a
// RuleResponse with no Exception is a failure (opa-utils RuleResponse.Failed),
// and GetFailedResources reads the object back out of AlertObject.K8SApiObjects.
func celRuleResponse(rule *reporthandling.PolicyRule, obj map[string]any, messages []string, hints []cel.PathHint) reporthandling.RuleResponse {
	return reporthandling.RuleResponse{
		AlertMessage:        strings.Join(messages, "; "),
		AssistedRemediation: celRemediation(hints),
		RuleStatus:          reporthandling.StatusFailed,
		PackageName:         rule.Name,
		Rulename:            rule.Name,
		AlertObject: reporthandling.AlertObject{
			K8SApiObjects: []map[string]any{obj},
		},
	}
}

// celRemediation maps the evaluator's neutral path hints onto the report
// model's remediation fields, so appendPaths gives a CEL failure the same
// ResourceAssociatedRule.Paths a Rego failure carries.
//
// A hint with a value says what the policy requires at that path, which is a
// fix `kubescape fix` can write into the YAML. A hint without one only says
// where the policy looked, so it becomes a review path: naming the field is
// useful, but inventing the value to put there would let `kubescape fix` write
// something the policy never asked for.
//
// Paths repeat across a policy's validations (the bundle guards each kind with
// its own validation, and several can name the same field), so they are
// deduplicated by path to keep one finding from listing the same path twice.
// The dedup is keyed on the path alone, not the whole hint: if the same path
// arrives once with a value and once without, it must land in exactly one of
// FixPaths or ReviewPaths, so the valued hint wins and the bare one is dropped.
func celRemediation(hints []cel.PathHint) reporthandling.AssistedRemediation {
	byPath := make(map[string]string, len(hints))
	order := make([]string, 0, len(hints))
	for _, hint := range hints {
		if existing, seen := byPath[hint.Path]; !seen {
			byPath[hint.Path] = hint.Value
			order = append(order, hint.Path)
		} else if existing == "" {
			byPath[hint.Path] = hint.Value // a valued hint supersedes a bare one
		}
	}

	var remediation reporthandling.AssistedRemediation
	for _, path := range order {
		if value := byPath[path]; value != "" {
			remediation.FixPaths = append(remediation.FixPaths, armotypes.FixPath{Path: path, Value: value})
			continue
		}
		remediation.ReviewPaths = append(remediation.ReviewPaths, path)
	}
	return remediation
}

// celResourceID labels an object in an eval-error message; it falls back to a
// placeholder when the object is not a recognizable envelope.
func celResourceID(obj map[string]any) string {
	if meta := objectsenvelopes.NewObject(obj); meta != nil {
		return meta.GetID()
	}
	return "<unknown>"
}

// opaRegisterOnce guards rego.RegisterBuiltin1/2 below. Those calls mutate
// OPA's process-global builtin registry (ast.Builtins/ast.BuiltinMap), which
// the OPA docs call out as not thread-safe and unsupported to call more than
// once per process. This must stay a package-level sync.Once: a field on
// OPAProcessor would give every new instance (i.e. every scan) its own,
// never-fired Once, defeating the "only once" guarantee it exists to provide.
var opaRegisterOnce sync.Once

// registerOPABuiltins registers kubescape's custom Rego builtins with the OPA
// runtime exactly once for the lifetime of the process, regardless of how
// many OPAProcessor instances (scans) are created. It stays idempotent (via
// opaRegisterOnce) even though init() below already calls it eagerly,
// because runRegoOnK8s and tests also call it directly.
func registerOPABuiltins() {
	opaRegisterOnce.Do(func() {
		rego.RegisterBuiltin2(cosignVerifySignatureDeclaration, cosignVerifySignatureDefinition)
		rego.RegisterBuiltin1(cosignHasSignatureDeclaration, cosignHasSignatureDefinition)
		rego.RegisterBuiltin1(imageNameNormalizeDeclaration, imageNameNormalizeDefinition)
	})
}

// Registering eagerly at package init, rather than lazily on the first scan,
// removes the (currently unused, but latent) window where a concurrent
// scan-triggering path could race the first call to registerOPABuiltins.
// The declarations/definitions it references are plain package-level vars
// with no runtime dependency, so they are already initialized by the time
// any init() func runs.
func init() {
	registerOPABuiltins()
}

// runRegoOnK8s compiles an OPA PolicyRule and evaluates its against k8s
func (opap *OPAProcessor) runRegoOnK8s(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, getRuleData func(*reporthandling.PolicyRule) string, ruleRegoDependenciesData resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	registerOPABuiltins()

	ruleData := getRuleData(rule)
	compiled, regoVersion, err := opap.getCompiledRule(ctx, rule.Name, ruleData, opap.printEnabled)
	if err != nil {
		return nil, fmt.Errorf("rule: '%s', %w", rule.Name, err)
	}

	store, err := ruleRegoDependenciesData.TOStorage()
	if err != nil {
		return nil, err
	}

	results, err := opap.regoEval(ctx, k8sObjects, compiled, regoVersion, &store)
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

func (opap *OPAProcessor) regoEval(ctx context.Context, inputObj []map[string]any, compiledRego *ast.Compiler, regoVersion ast.RegoVersion, store *storage.Store) ([]reporthandling.RuleResponse, error) {
	rego := rego.New(
		rego.SetRegoVersion(regoVersion),
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

// enumerateData resolves a rule's ResourceEnumerator. A CEL rule must not carry
// one (it scopes via the VAP's matchConstraints); the guard below enforces that
// rather than trusting it, because routing a CEL rule through the enumerator
// would run its validations as the enumerator and silently drop every compliant
// resource. So the enumerator path here is provably the Rego path, and controlID
// is unused on it.
func (opap *OPAProcessor) enumerateData(ctx context.Context, rule *reporthandling.PolicyRule, k8sObjects []map[string]any, controlID string) ([]map[string]any, error) {
	if ruleEnumeratorData(rule) == "" {
		return k8sObjects, nil
	}
	if rule.RuleLanguage == reporthandling.CELLanguage {
		return nil, fmt.Errorf("rule: '%s', CEL rules must not declare a ResourceEnumerator; they scope via the policy's matchConstraints", rule.Name)
	}

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, nil)
	ruleResponse, _, err := opap.runOPAOnSingleRule(ctx, rule, k8sObjects, ruleEnumeratorData, ruleRegoDependenciesData, controlID)
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

// getCompiledRule compiles ruleName+ruleData together with the shared rule
// dependencies, preferring Rego v1. Policy sources that predate the
// regolibrary/opa-utils v1 migration - a pinned --controls-version release,
// a --use-from/--use-default air-gapped bundle, or a tenant-authored custom
// control from the cloud backend - are plain v0 syntax with no "import
// rego.v1" marker, so the v1 parse fails outright; falling back to v0 keeps
// those inputs scannable instead of producing a fatal, empty-report exit.
// Modules that do declare "import rego.v1" parse identically under either
// default, so this only changes behavior for genuinely legacy v0 rules.
func (opap *OPAProcessor) getCompiledRule(ctx context.Context, ruleName, ruleData string, printEnabled bool) (*ast.Compiler, ast.RegoVersion, error) {
	cacheKey := ruleName + "|" + ruleData

	opap.compiledMu.RLock()
	if entry, ok := opap.compiledModules[cacheKey]; ok {
		opap.compiledMu.RUnlock()
		return entry.compiler, entry.version, nil
	}
	opap.compiledMu.RUnlock()

	opap.compiledMu.Lock()
	defer opap.compiledMu.Unlock()

	if entry, ok := opap.compiledModules[cacheKey]; ok {
		return entry.compiler, entry.version, nil
	}

	baseModules, err := getRuleDependencies(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get rule dependencies: %w", err)
	}

	modules := make(map[string]string, len(baseModules)+1)
	maps.Copy(modules, baseModules)
	modules[ruleName] = ruleData

	version := ast.RegoV1
	compiled, v1Err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: printEnabled,
		ParserOptions:         ast.ParserOptions{RegoVersion: ast.RegoV1},
	})
	if v1Err != nil {
		var v0Err error
		compiled, v0Err = ast.CompileModulesWithOpt(modules, ast.CompileOpts{
			EnablePrintStatements: printEnabled,
			ParserOptions:         ast.ParserOptions{RegoVersion: ast.RegoV0},
		})
		if v0Err != nil {
			return nil, 0, fmt.Errorf("failed to compile rule '%s': %w", ruleName, v1Err)
		}
		version = ast.RegoV0
		logger.L().Ctx(ctx).Warning("rule uses deprecated Rego v0 syntax; v0 support will be removed in a future release",
			helpers.String("rule", ruleName))
	}

	opap.compiledModules[cacheKey] = compiledRule{compiler: compiled, version: version}
	return compiled, version, nil
}

// createLightweightResource is intentionally removed. Stripping spec/status/data
// from resources stored in opap.AllResources broke downstream stages (printers,
// image scanning, prioritisation, exception matching) that read the full object.
// The streaming path now stores the original resource, matching the non-streaming
// path's behaviour.
