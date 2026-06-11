package cautils

import (
	"sort"

	"github.com/kubescape/opa-utils/reporthandling/apis"
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
// A control is considered NotEvaluated when every GVR listed in
// ResourceToControlsMap for that control appears in InfoMap as a pull failure,
// or when it appears in timedOutControls because its evaluation was aborted
// (e.g. by exceeding --control-timeout).
// Controls with at least one successfully fetched GVR are not included.
//
// InfoMap is mixed-purpose: it holds whole-GVR pull failures (keyed by GVR
// string) AND resource-level OPA evaluation skips (keyed by resource ID). To
// avoid surfacing per-resource eval skips as GVR pull failures, only InfoMap
// entries whose key is also a key in ResourceToControlsMap are considered.
//
// partialPulls carries per-selector LIST failures for GVRs that were partially
// collected; they are included as-is in ScanCoverage.PartialGVRPulls.
func BuildScanCoverage(infoMap map[string]apis.StatusInfo, resourceToControlsMap map[string][]string, timedOutControls map[string]string, partialPulls []PartialGVRPull) ScanCoverage {
	coverage := ScanCoverage{
		PartialGVRPulls: partialPulls,
	}

	notEvaluated := make(map[string]NotEvaluatedControl, len(timedOutControls))

	for controlID, reason := range timedOutControls {
		notEvaluated[controlID] = NotEvaluatedControl{
			ControlID: controlID,
			Reason:    reason,
		}
	}

	if len(infoMap) == 0 {
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
		// eval skips by requiring the key to be a known GVR
		for gvr, statusInfo := range infoMap {
			if statusInfo.InnerStatus != apis.StatusSkipped {
				continue
			}
			if _, isGVR := resourceToControlsMap[gvr]; !isGVR {
				continue
			}
			coverage.FailedGVRPulls = append(coverage.FailedGVRPulls, FailedGVRPull{
				GVR:   gvr,
				Error: statusInfo.InnerInfo,
			})
		}

		if len(coverage.FailedGVRPulls) > 0 {
			// build a set of failed GVRs for fast lookup
			failedGVRs := make(map[string]struct{}, len(coverage.FailedGVRPulls))
			for _, f := range coverage.FailedGVRPulls {
				failedGVRs[f.GVR] = struct{}{}
			}

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
					if _, failed := failedGVRs[gvr]; failed {
						missingGVRs = append(missingGVRs, gvr)
					} else {
						allFailed = false
						break
					}
				}
				if allFailed && len(missingGVRs) == len(gvrSet) {
					sort.Strings(missingGVRs)
					notEvaluated[controlID] = NotEvaluatedControl{
						ControlID:   controlID,
						MissingGVRs: missingGVRs,
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
