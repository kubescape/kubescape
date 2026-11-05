package opaprocessor

import (
	"cmp"
	"context"
	"slices"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
)

// cacheWriteState collects, for one processControl call, what its rule
// evaluations may contribute to the incremental cache. It is only accessed
// from the goroutine running that call.
//
// Nothing reaches the cache before it is verified: processControl turns the
// state into a cacheCandidate, and storeVerifiedCandidate writes the verified
// part of it. With deferred set, processControl leaves the candidate for the
// caller to verify after the control's timed window (see processScope);
// otherwise processControl verifies and stores it itself.
type cacheWriteState struct {
	// unsafe reports that some rule's results cannot be stored at all.
	unsafe bool
	// deferred makes processControl hand the candidate to its caller.
	deferred bool
	// records are the cached rule evaluations to verify.
	records []ruleEvaluationRecord
	// candidate is set by processControl when deferred is set.
	candidate *cacheCandidate
}

func (s *cacheWriteState) markUnsafe() {
	if s != nil {
		s.unsafe = true
	}
}

func (s *cacheWriteState) isUnsafe() bool {
	return s != nil && s.unsafe
}

func (s *cacheWriteState) addRecord(record ruleEvaluationRecord) {
	if s != nil {
		s.records = append(s.records, record)
	}
}

// ruleAttribution is what a cached evaluation of one rule learned about
// whether its results can be used and stored.
type ruleAttribution struct {
	// cacheHits counts the objects whose verdicts were replayed from the
	// cache instead of being evaluated.
	cacheHits int
	// unsafe reports that a finding names an object this evaluation did not
	// evaluate, so results mixed with replayed verdicts can be wrong and none
	// of them can be stored.
	unsafe bool
	reason string
}

// recordedVerdict is one object's verdict under one rule, copied when the
// rule finished so later merges of the result maps cannot change it.
type recordedVerdict struct {
	status apis.ScanningStatus
	paths  []armotypes.PosturePaths
}

// ruleEvaluationRecord is what verifying one cached rule evaluation needs.
type ruleEvaluationRecord struct {
	rule *reporthandling.PolicyRule
	deps resources.RegoDependenciesData
	// evaluated holds the raw objects Rego evaluated, by resource ID: the
	// matched objects without the cache hits, before any enumerator.
	evaluated map[string]map[string]any
	// cacheHits are the objects whose verdicts were replayed.
	cacheHits map[string]struct{}
	// verdicts are the rule's results, including replayed ones.
	verdicts map[string]recordedVerdict
}

func newRuleEvaluationRecord(rule *reporthandling.PolicyRule, deps resources.RegoDependenciesData, evaluated map[string]map[string]any, cacheHits map[string]struct{}, results map[string]*resourcesresults.ResourceAssociatedRule) ruleEvaluationRecord {
	verdicts := make(map[string]recordedVerdict, len(results))
	for id, result := range results {
		if result != nil {
			verdicts[id] = recordedVerdict{status: result.Status, paths: slices.Clone(result.Paths)}
		}
	}
	return ruleEvaluationRecord{rule: rule, deps: deps, evaluated: evaluated, cacheHits: cacheHits, verdicts: verdicts}
}

// cacheCandidate is everything one processControl call would write to the
// cache, before verification.
type cacheCandidate struct {
	controlID string
	records   []ruleEvaluationRecord
	entries   []cacheCandidateEntry
}

type cacheCandidateEntry struct {
	resourceID string
	hash       string
	verdict    resourcesresults.ResourceAssociatedControl
}

// newCacheCandidate captures the control's results with each resource's hash
// as it is when the control finishes, as the cache write always has.
func (opap *OPAProcessor) newCacheCandidate(controlID string, records []ruleEvaluationRecord, results map[string]resourcesresults.ResourceAssociatedControl) *cacheCandidate {
	candidate := &cacheCandidate{controlID: controlID, records: records}
	for resourceID, result := range results {
		resource, ok := opap.GetResource(resourceID)
		if !ok {
			continue
		}
		candidate.entries = append(candidate.entries, cacheCandidateEntry{
			resourceID: resourceID,
			hash:       scancache.ResourceHash(resource.GetObject()),
			verdict:    result,
		})
	}
	return candidate
}

// attributedFailedResources returns the objects a rule response attributes a
// failure to, after the namespace and enumerator filters that decide which
// attributions are kept. Every consumer of attributions uses it, so the
// cache's verification sees exactly what results are built from.
func (opap *OPAProcessor) attributedFailedResources(response reporthandling.RuleResponse, enumeratedIDs map[string]struct{}) []workloadinterface.IMetadata {
	var attributed []workloadinterface.IMetadata
	for _, failedResource := range objectsenvelopes.ListMapToMeta(response.GetFailedResources()) {
		if opap.skipNamespace(failedResource.GetNamespace()) {
			continue
		}
		if !inEnumeratedScope(enumeratedIDs, failedResource, failedResource.GetID()) {
			continue
		}
		attributed = append(attributed, failedResource)
	}
	return attributed
}

// reportedObjects returns every object a rule response reports a failure for,
// after only the namespace filter. The enumerator filter is left out on
// purpose: the enumerated scope is built from the objects evaluated in this
// scan, which excludes cache hits, so it would hide a finding against a cache
// hit that a full scan keeps.
func (opap *OPAProcessor) reportedObjects(response reporthandling.RuleResponse) []workloadinterface.IMetadata {
	var reported []workloadinterface.IMetadata
	for _, object := range objectsenvelopes.ListMapToMeta(response.GetFailedResources()) {
		if opap.skipNamespace(object.GetNamespace()) {
			continue
		}
		reported = append(reported, object)
	}
	return reported
}

// precheckCacheAttribution is the check a cached evaluation needs before its
// results are used: every finding must name an object this evaluation
// evaluated. A finding naming any other object (a cache hit, an object of
// another scope, a synthesized identity) means the replayed verdicts may be
// missing or hiding it. It costs no evaluation, so it runs inside the
// control's timed window; the per-object verification runs later.
//
// evaluated is the raw input Rego evaluated: the matched objects without the
// cache hits, before any enumerator. It returns that input by resource ID.
func (opap *OPAProcessor) precheckCacheAttribution(evaluated []map[string]any, responses []reporthandling.RuleResponse) (map[string]map[string]any, bool, string) {
	evaluatedObjects := objectsenvelopes.ListMapToMeta(evaluated)
	if len(evaluatedObjects) != len(evaluated) {
		return nil, false, "an evaluated object has no resource identity"
	}
	evaluatedByID := make(map[string]map[string]any, len(evaluatedObjects))
	for _, object := range evaluatedObjects {
		id := object.GetID()
		if _, duplicate := evaluatedByID[id]; duplicate {
			return nil, false, "two evaluated objects share the identity " + id
		}
		evaluatedByID[id] = object.GetObject()
	}

	for _, response := range responses {
		if len(response.RelatedObjects) > 0 {
			return nil, false, "a finding names related objects"
		}
		for _, reported := range opap.reportedObjects(response) {
			if _, ok := evaluatedByID[reported.GetID()]; !ok {
				return nil, false, "a finding is reported for an object that was not evaluated: " + reported.GetID()
			}
		}
	}
	return evaluatedByID, true, ""
}

// verificationContext bounds the verification of one control's cache
// candidate. It is separate from the control's evaluation timeout: the
// verification only decides what is stored, so it must not count against the
// time the control has to produce its results. It gets the same budget,
// ControlTimeout, when one is set, and is otherwise bounded only by ctx, as
// evaluation is.
func (opap *OPAProcessor) verificationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if opap.ControlTimeout > 0 {
		return context.WithTimeout(ctx, opap.ControlTimeout)
	}
	return context.WithCancel(ctx)
}

// storeVerifiedCandidate writes the verified part of candidate to the cache.
//
// An object is stored only if, under every rule that evaluated it, its own
// evaluation reproduces exactly the verdict the batch gave it and reports
// nothing but the object itself (see verifyRecord). Under a rule that replayed
// its verdict instead, the replayed verdict was verified when it was stored.
// Objects that received a verdict without being evaluated are never stored.
//
// Storing per object is sound: when another object's finding is attributed
// to an object, that object's batch verdict differs from its own and it is
// not stored, and neither is the reporter, whose own evaluation names
// another object. A later finding against a stored object is caught by
// precheckCacheAttribution, since a cache hit is never evaluated.
//
// Verification never changes the scan's results, only what is stored. If it
// fails, errors or runs out of time, the affected objects are not stored.
func (opap *OPAProcessor) storeVerifiedCandidate(ctx context.Context, candidate *cacheCandidate) {
	if candidate == nil || opap.incrementalCache == nil {
		return
	}
	if len(candidate.entries) == 0 {
		return
	}
	vctx, cancel := opap.verificationContext(ctx)
	defer cancel()

	// Only objects that would be stored need verifying: each object is
	// verified on its own, so skipping the others changes nothing stored.
	candidates := make(map[string]struct{}, len(candidate.entries))
	for _, entry := range candidate.entries {
		candidates[entry.resourceID] = struct{}{}
	}
	unverified := map[string]struct{}{}
	for _, record := range candidate.records {
		for id := range opap.verifyRecord(vctx, candidate.controlID, record, candidates) {
			unverified[id] = struct{}{}
		}
	}

	stored := 0
	for _, entry := range candidate.entries {
		if _, rejected := unverified[entry.resourceID]; rejected {
			continue
		}
		opap.incrementalCache.Put(candidate.controlID, entry.resourceID, entry.hash, entry.verdict)
		stored++
	}
	if len(unverified) > 0 {
		logger.L().Ctx(ctx).Debug("incremental cache: objects not stored because their verdicts could not be verified per object",
			helpers.String("controlID", candidate.controlID),
			helpers.Int("stored", stored),
			helpers.Int("notStored", len(unverified)))
	}
}

// verifyRecord returns the objects of one rule evaluation that must not be
// stored. Evaluated objects outside candidates are not stored either way and
// are skipped.
func (opap *OPAProcessor) verifyRecord(ctx context.Context, controlID string, record ruleEvaluationRecord, candidates map[string]struct{}) map[string]struct{} {
	rejected := map[string]struct{}{}

	// A verdict for an object that was neither evaluated nor replayed was
	// produced from other objects, e.g. by an enumerator's output.
	for id := range record.verdicts {
		_, evaluated := record.evaluated[id]
		_, replayed := record.cacheHits[id]
		if !evaluated && !replayed {
			rejected[id] = struct{}{}
		}
	}

	for id, object := range record.evaluated {
		if _, wanted := candidates[id]; !wanted {
			continue
		}
		if ctx.Err() != nil {
			rejected[id] = struct{}{}
			continue
		}
		alone, ok := opap.isolatedRuleVerdict(ctx, controlID, record, id, object)
		if !ok {
			rejected[id] = struct{}{}
			continue
		}
		batch, inBatch := record.verdicts[id]
		if alone.present != inBatch || alone.verdict.status != batch.status {
			rejected[id] = struct{}{}
			continue
		}
		if alone.verdict.status == apis.StatusFailed && !samePosturePaths(alone.verdict.paths, batch.paths) {
			rejected[id] = struct{}{}
		}
	}
	return rejected
}

// isolatedVerdict is an object's verdict computed from the object alone.
type isolatedVerdict struct {
	present bool
	verdict recordedVerdict
}

// isolatedRuleVerdict computes the verdict the rule gives the object with
// resource ID id when it is the rule's only input, the way the batch computes
// it: the enumerator decides whether the object is in scope, the rule's
// findings for the object make it fail, and an object in scope without a
// finding passes. It uses the same rule source, policy inputs and control ID
// as the batch.
//
// It reports false when the object alone does anything that ties its verdict
// to other objects or cannot be reproduced: the enumerator or the rule names
// another object, a finding names related objects, or an evaluation errors.
func (opap *OPAProcessor) isolatedRuleVerdict(ctx context.Context, controlID string, record ruleEvaluationRecord, id string, object map[string]any) (isolatedVerdict, bool) {
	input := []map[string]any{object}

	// Scope membership comes from the object alone, never from the batch:
	// in the batch, another object's enumeration can put this one in scope.
	var enumeratedIDs map[string]struct{}
	inPassScope := true
	if ruleEnumeratorData(record.rule) != "" {
		outputs, err := opap.enumerateData(ctx, record.rule, input, controlID)
		if err != nil {
			return isolatedVerdict{}, false
		}
		enumerated := objectsenvelopes.ListMapToMeta(outputs)
		if len(enumerated) != len(outputs) {
			return isolatedVerdict{}, false
		}
		enumeratedIDs = map[string]struct{}{}
		inPassScope = false
		for _, output := range enumerated {
			if objectsenvelopes.GetObjectType(output.GetObject()) == objectsenvelopes.TypeRegoResponseVectorObject || output.GetID() != id {
				return isolatedVerdict{}, false
			}
			enumeratedIDs[id] = struct{}{}
			inPassScope = true
		}
	}

	responses, _, err := opap.runOPAOnSingleRule(ctx, record.rule, input, ruleData, record.deps, controlID)
	if err != nil {
		return isolatedVerdict{}, false
	}
	var paths []armotypes.PosturePaths
	failed := false
	for _, response := range responses {
		if len(response.RelatedObjects) > 0 {
			return isolatedVerdict{}, false
		}
		for _, reported := range opap.reportedObjects(response) {
			if reported.GetID() != id {
				return isolatedVerdict{}, false
			}
		}
		for range opap.attributedFailedResources(response, enumeratedIDs) {
			failed = true
			paths = appendPaths(paths, response.AssistedRemediation, id)
		}
	}

	switch {
	case failed:
		return isolatedVerdict{present: true, verdict: recordedVerdict{status: apis.StatusFailed, paths: paths}}, true
	case inPassScope:
		return isolatedVerdict{present: true, verdict: recordedVerdict{status: apis.StatusPassed}}, true
	default:
		return isolatedVerdict{}, true
	}
}

// logCacheAttributionViolation records why a rule's results were kept out of
// the incremental cache.
func logCacheAttributionViolation(ctx context.Context, controlID string, rule *reporthandling.PolicyRule, attribution ruleAttribution) {
	logger.L().Ctx(ctx).Debug("incremental cache: a finding names an object this evaluation did not evaluate; not storing the results",
		helpers.String("controlID", controlID),
		helpers.String("rule", rule.Name),
		helpers.Int("cacheHits", attribution.cacheHits),
		helpers.String("reason", attribution.reason))
}

// samePosturePaths reports whether a and b hold the same paths the same
// number of times, in any order.
func samePosturePaths(a, b []armotypes.PosturePaths) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, comparePosturePaths)
	slices.SortFunc(b, comparePosturePaths)
	return slices.Equal(a, b)
}

func comparePosturePaths(a, b armotypes.PosturePaths) int {
	return cmp.Or(
		cmp.Compare(a.ResourceID, b.ResourceID),
		cmp.Compare(a.FailedPath, b.FailedPath),
		cmp.Compare(a.ReviewPath, b.ReviewPath),
		cmp.Compare(a.DeletePath, b.DeletePath),
		cmp.Compare(a.FixPath.Path, b.FixPath.Path),
		cmp.Compare(a.FixPath.Value, b.FixPath.Value),
		cmp.Compare(a.FixCommand, b.FixCommand),
	)
}
