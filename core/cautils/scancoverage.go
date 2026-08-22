package cautils

import (
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// ScanCoverage holds runtime gaps discovered during a scan: GVRs that could
// not be pulled and controls that were therefore never evaluated. This is
// distinct from configured scope (include/exclude namespaces) which lives in
// scanMetadata.
type ScanCoverage struct {
	FailedGVRPulls       []FailedGVRPull       `json:"failedGVRPulls,omitempty"`
	NotEvaluatedControls []NotEvaluatedControl `json:"notEvaluatedControls,omitempty"`
	// PartialGVRPulls records per-selector LIST failures for GVRs that had at
	// least one successful query. Controls are still evaluated against the
	// partial data, but this field surfaces the gap so operators and CI/CD
	// pipelines can detect incomplete scans without a false-green result.
	PartialGVRPulls []PartialGVRPull `json:"partialGVRPulls,omitempty"`
	// PolicyDegradations records policy inputs (control configurations,
	// exceptions) that could not be loaded from their configured source and
	// were served from a fallback so the scan could proceed.
	PolicyDegradations []PolicyDegradation `json:"policyDegradations,omitempty"`
	// CoverageScore is an aggregate 0-100 measure of how complete the scan was:
	// the ratio of evaluated controls, discounted for partial resource pulls
	// and degraded policy inputs. It is computed once by ComputeCoverageScore.
	CoverageScore float32 `json:"coverageScore"`
	// EvaluatedControls is the number of controls that were actually evaluated.
	EvaluatedControls int `json:"evaluatedControls"`
	// TotalControls is the number of controls in scope for the scan.
	TotalControls int `json:"totalControls"`
	// Degraded is true when the scan was not fully complete (CoverageScore < 100).
	Degraded bool `json:"degraded"`
	// SilentFailedGVRCount is the number of failed GVR pulls that are silent:
	// at least one control depending on the GVR still evaluated via other GVRs,
	// so the failure is not already accounted for by NotEvaluatedControls. It is
	// computed by BuildScanCoverage and applied as a penalty by ComputeCoverageScore.
	SilentFailedGVRCount int `json:"silentFailedGVRCount,omitempty"`
	// VacuousFrameworks lists frameworks whose reported score is 100% only
	// because every control in them was Irrelevant (no resource of the
	// required type was found in the cluster), not because anything was
	// actually checked. Populated by DetectVacuousFrameworks.
	VacuousFrameworks []string `json:"vacuousFrameworks,omitempty"`
}

// Fixed penalties (in percentage points) applied to the coverage score for
// each incompleteness that does not by itself mark a control unevaluated.
const (
	failedGVRPullPenalty     float32 = 3
	partialGVRPullPenalty    float32 = 2
	policyDegradationPenalty float32 = 5
)

// ComputeCoverageScore derives CoverageScore from the controls actually
// evaluated, discounted by a fixed penalty for every silent failed GVR pull,
// every partial GVR pull, and every degraded policy input. The result is
// clamped to [0, 100]. totalControls is the number of controls in scope.
// This is the single point where the score is computed so that every consumer
// reports an identical value.
func (c *ScanCoverage) ComputeCoverageScore(totalControls int) {
	c.TotalControls = totalControls
	c.EvaluatedControls = totalControls - len(c.NotEvaluatedControls)
	if c.EvaluatedControls < 0 {
		c.EvaluatedControls = 0
	}

	var score float32
	if totalControls == 0 {
		// No controls in scope means nothing was evaluated — report 0%
		// coverage rather than a misleading 100%.
		score = 0
	} else {
		score = float32(c.EvaluatedControls) / float32(totalControls) * 100
	}

	score -= failedGVRPullPenalty * float32(c.SilentFailedGVRCount)
	score -= partialGVRPullPenalty * float32(len(c.PartialGVRPulls))
	score -= policyDegradationPenalty * float32(len(c.PolicyDegradations))

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	c.CoverageScore = score
	c.Degraded = totalControls == 0 || len(c.FailedGVRPulls) > 0 || len(c.PartialGVRPulls) > 0 ||
		len(c.PolicyDegradations) > 0 || len(c.NotEvaluatedControls) > 0
}

// PolicyDegradation records a policy input that could not be loaded from its
// configured source (Kubescape Cloud, ControlInput CRD, regolibrary release,
// or a local file) and was served from a fallback instead.
type PolicyDegradation struct {
	// Component identifies the degraded input, e.g. "controlInputs" or "exceptions".
	Component string `json:"component"`
	// Reason is the error returned by the configured source.
	Reason string `json:"reason"`
}

// FailedGVRPull records a single GVR whose resources could not be collected.
type FailedGVRPull struct {
	GVR   string `json:"gvr"`
	Error string `json:"error"`
}

// PartialGVRPull records a LIST failure scoped to a specific field selector
// (e.g. a namespace or name selector) for a GVR that was otherwise partially
// collected. Unlike FailedGVRPull, other queries for the same GVR succeeded,
// so controls are evaluated against an incomplete resource set.
// Discovery-stage failures use the self-describing GVR form
// "discovery:<group/version>" (or "discovery:*" when no group is available)
// together with Selector "discovery".
type PartialGVRPull struct {
	GVR      string `json:"gvr"`
	Selector string `json:"selector"`
	Error    string `json:"error"`
}

// NotEvaluatedControl records a control that was not evaluated, either
// because every GVR it depends on failed to pull (MissingGVRs is set) or
// because its evaluation was aborted during the OPA processing phase, e.g.
// by exceeding --control-timeout (Reason is set).
type NotEvaluatedControl struct {
	ControlID   string   `json:"controlID"`
	MissingGVRs []string `json:"missingGVRs,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// BuildScanCoverage derives a ScanCoverage from the InfoMap,
// ResourceToControlsMap, timedOutControls, and any partial GVR pull failures
// on the session.
//
// A control is considered NotEvaluated when every dependency listed in
// ResourceToControlsMap for that control either appears in InfoMap as a pull
// failure or is a mapped discovery failure in partialPulls, or when it appears
// in timedOutControls because its evaluation was aborted (e.g. by exceeding
// --control-timeout).
// Controls with at least one successfully fetched GVR are not included.
//
// InfoMap is mixed-purpose: it holds whole-GVR pull failures (keyed by GVR
// string) AND resource-level OPA evaluation skips (keyed by resource ID). To
// avoid surfacing per-resource eval skips as GVR pull failures, only InfoMap
// entries whose key is also a key in ResourceToControlsMap are considered.
//
// partialPulls carries per-selector LIST failures for GVRs that were partially
// collected; they are included in canonical order in
// ScanCoverage.PartialGVRPulls. A
// discovery-stage failure that has a synthetic ResourceToControlsMap edge also
// participates in the all-dependencies-failed check without being duplicated
// in FailedGVRPulls.
//
// policyDegradations carries policy inputs (control configurations,
// exceptions) that were served from a fallback; they are included as-is in
// ScanCoverage.PolicyDegradations.
func BuildScanCoverage(infoMap map[string]apis.StatusInfo, resourceToControlsMap map[string][]string, timedOutControls map[string]string, partialPulls []PartialGVRPull, policyDegradations []PolicyDegradation) ScanCoverage {
	sortedPartialPulls := append([]PartialGVRPull(nil), partialPulls...)
	sort.Slice(sortedPartialPulls, func(i, j int) bool {
		if sortedPartialPulls[i].GVR != sortedPartialPulls[j].GVR {
			return sortedPartialPulls[i].GVR < sortedPartialPulls[j].GVR
		}
		if sortedPartialPulls[i].Selector != sortedPartialPulls[j].Selector {
			return sortedPartialPulls[i].Selector < sortedPartialPulls[j].Selector
		}
		return sortedPartialPulls[i].Error < sortedPartialPulls[j].Error
	})
	coverage := ScanCoverage{
		PartialGVRPulls:    sortedPartialPulls,
		PolicyDegradations: policyDegradations,
	}

	notEvaluated := make(map[string]NotEvaluatedControl, len(timedOutControls))
	discoveryFailureKeys := make(map[string]struct{})
	failedDependencyKeys := make(map[string]struct{})
	for _, partialPull := range partialPulls {
		if partialPull.Selector != "discovery" || !strings.HasPrefix(partialPull.GVR, "discovery:") {
			continue
		}
		discoveryFailureKeys[partialPull.GVR] = struct{}{}
		if _, mappedToControl := resourceToControlsMap[partialPull.GVR]; mappedToControl {
			failedDependencyKeys[partialPull.GVR] = struct{}{}
		}
	}

	for controlID, reason := range timedOutControls {
		notEvaluated[controlID] = NotEvaluatedControl{
			ControlID: controlID,
			Reason:    reason,
		}
	}

	if len(infoMap) == 0 && len(failedDependencyKeys) == 0 {
		for _, ne := range notEvaluated {
			coverage.NotEvaluatedControls = append(coverage.NotEvaluatedControls, ne)
		}
		sort.Slice(coverage.NotEvaluatedControls, func(i, j int) bool {
			return coverage.NotEvaluatedControls[i].ControlID < coverage.NotEvaluatedControls[j].ControlID
		})
		return coverage
	}

	if len(resourceToControlsMap) > 0 {
		// collect failed GVR pulls from InfoMap, filtering out resource-level
		// eval skips by requiring the key to be a known dependency. Discovery
		// failures are already reported in PartialGVRPulls, so keep them in the
		// dependency set without duplicating them in FailedGVRPulls.
		for gvr, statusInfo := range infoMap {
			if statusInfo.InnerStatus != apis.StatusSkipped {
				continue
			}
			if _, isGVR := resourceToControlsMap[gvr]; !isGVR {
				continue
			}
			failedDependencyKeys[gvr] = struct{}{}
			if _, isDiscoveryFailure := discoveryFailureKeys[gvr]; isDiscoveryFailure {
				continue
			}
			coverage.FailedGVRPulls = append(coverage.FailedGVRPulls, FailedGVRPull{
				GVR:   gvr,
				Error: statusInfo.InnerInfo,
			})
		}

		if len(failedDependencyKeys) > 0 {
			// invert ResourceToControlsMap: controlID -> set of GVRs it depends on
			controlToGVRs := make(map[string]map[string]struct{})
			for gvr, controlIDs := range resourceToControlsMap {
				for _, controlID := range controlIDs {
					if _, ok := controlToGVRs[controlID]; !ok {
						controlToGVRs[controlID] = make(map[string]struct{})
					}
					controlToGVRs[controlID][gvr] = struct{}{}
				}
			}

			// a control is not-evaluated only when ALL its GVRs are in the failed set
			for controlID, gvrSet := range controlToGVRs {
				if _, ok := notEvaluated[controlID]; ok {
					continue
				}
				missingGVRs := make([]string, 0, len(gvrSet))
				allFailed := true
				for gvr := range gvrSet {
					if _, failed := failedDependencyKeys[gvr]; failed {
						missingGVRs = append(missingGVRs, gvr)
					} else if _, attempted := infoMap[gvr]; attempted {
						allFailed = false
						break
					}
				}
				if allFailed && len(missingGVRs) > 0 {
					sort.Strings(missingGVRs)
					notEvaluated[controlID] = NotEvaluatedControl{
						ControlID:   controlID,
						MissingGVRs: missingGVRs,
					}
				}
			}

			// a failed GVR is silent (and incurs a penalty) when at least one
			// of its dependent controls still evaluated via other GVRs, i.e. is
			// not in notEvaluated. Only when ALL dependents are not-evaluated is
			// the failure already fully charged via the ratio.
			for _, f := range coverage.FailedGVRPulls {
				for _, controlID := range resourceToControlsMap[f.GVR] {
					if _, ok := notEvaluated[controlID]; !ok {
						coverage.SilentFailedGVRCount++
						break
					}
				}
			}
		}

		sort.Slice(coverage.FailedGVRPulls, func(i, j int) bool {
			return coverage.FailedGVRPulls[i].GVR < coverage.FailedGVRPulls[j].GVR
		})
	}

	for _, ne := range notEvaluated {
		coverage.NotEvaluatedControls = append(coverage.NotEvaluatedControls, ne)
	}
	sort.Slice(coverage.NotEvaluatedControls, func(i, j int) bool {
		return coverage.NotEvaluatedControls[i].ControlID < coverage.NotEvaluatedControls[j].ControlID
	})

	return coverage
}

// DetectVacuousFrameworks returns the names of frameworks whose controls are
// all Irrelevant (GetSubStatus() == apis.SubStatusIrrelevant with no matched
// resources), mirroring the check the scoring library uses to award such a
// framework a 100% score. A framework in this state was never meaningfully
// evaluated - no resource in the cluster matched any of its controls - so
// its perfect score is vacuous rather than earned. Empty frameworks (no
// controls at all) are not included.
func DetectVacuousFrameworks(frameworks []reportsummary.FrameworkSummary) []string {
	var vacuous []string
	for i := range frameworks {
		fw := frameworks[i]
		if len(fw.Controls) == 0 {
			continue
		}
		allIrrelevant := true
		for id := range fw.Controls {
			ctrl := fw.Controls[id]
			if ctrl.GetSubStatus() != apis.SubStatusIrrelevant || ctrl.ListResourcesIDs(nil).Len() != 0 {
				allIrrelevant = false
				break
			}
		}
		if allIrrelevant {
			vacuous = append(vacuous, fw.Name)
		}
	}
	return vacuous
}
