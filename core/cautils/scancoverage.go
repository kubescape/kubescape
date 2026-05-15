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
}

// FailedGVRPull records a single GVR whose resources could not be collected.
type FailedGVRPull struct {
	GVR   string `json:"gvr"`
	Error string `json:"error"`
}

// NotEvaluatedControl records a control that was skipped because every GVR it
// depends on failed to pull.
type NotEvaluatedControl struct {
	ControlID   string   `json:"controlID"`
	MissingGVRs []string `json:"missingGVRs"`
}

// BuildScanCoverage derives a ScanCoverage from the InfoMap and
// ResourceToControlsMap on the session object.
//
// A control is considered NotEvaluated when every GVR listed in
// ResourceToControlsMap for that control appears in InfoMap as a pull failure.
// Controls with at least one successfully fetched GVR are not included.
//
// InfoMap is mixed-purpose: it holds whole-GVR pull failures (keyed by GVR
// string) AND resource-level OPA evaluation skips (keyed by resource ID). To
// avoid surfacing per-resource eval skips as GVR pull failures, only InfoMap
// entries whose key is also a key in ResourceToControlsMap are considered.
func BuildScanCoverage(infoMap map[string]apis.StatusInfo, resourceToControlsMap map[string][]string) ScanCoverage {
	coverage := ScanCoverage{}

	if len(infoMap) == 0 || len(resourceToControlsMap) == 0 {
		return coverage
	}

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

	if len(coverage.FailedGVRPulls) == 0 {
		return coverage
	}

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
			coverage.NotEvaluatedControls = append(coverage.NotEvaluatedControls, NotEvaluatedControl{
				ControlID:   controlID,
				MissingGVRs: missingGVRs,
			})
		}
	}

	// stable, deterministic output for JSON / golden tests
	sort.Slice(coverage.FailedGVRPulls, func(i, j int) bool {
		return coverage.FailedGVRPulls[i].GVR < coverage.FailedGVRPulls[j].GVR
	})
	sort.Slice(coverage.NotEvaluatedControls, func(i, j int) bool {
		return coverage.NotEvaluatedControls[i].ControlID < coverage.NotEvaluatedControls[j].ControlID
	})

	return coverage
}
