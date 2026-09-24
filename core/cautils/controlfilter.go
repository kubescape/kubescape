package cautils

import (
	"errors"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/reporthandling"
)

// ErrIncludeControlsNoMatch is returned when --include-controls is set but
// matches no known control.
var ErrIncludeControlsNoMatch = errors.New("--include-controls matched no known control")

// ErrNoControlsAfterFilter is returned when --include-controls/--skip-controls
// leave no controls to scan.
var ErrNoControlsAfterFilter = errors.New("--include-controls/--skip-controls left no controls to scan")

// SplitCommaList splits a comma-separated flag value into trimmed non-empty
// tokens.
func SplitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// ControlIdentifiers returns every name a control can be addressed by on the
// command line: its Kubescape control ID (ControlID, e.g. "C-0286") and,
// where the control carries one, its framework section number (Control_ID,
// e.g. "CIS-3.1.1"). Both are lowercased so lookups are case-insensitive.
// This is the same identifier pair policyhandler.markControlMatches uses, so
// --skip-controls and --include-controls accept exactly what
// --exclude-controls accepts.
func ControlIdentifiers(control *reporthandling.Control) []string {
	identifiers := make([]string, 0, 2)
	for _, identifier := range [2]string{control.ControlID, control.Control_ID} {
		token := strings.ToLower(strings.TrimSpace(identifier))
		if token == "" || slices.Contains(identifiers, token) {
			continue
		}
		identifiers = append(identifiers, token)
	}
	return identifiers
}

// ControlMatchesAny reports whether any identifier the control can be named
// by appears in set. set is expected to hold normalized (lowercased,
// trimmed) tokens.
func ControlMatchesAny(control *reporthandling.Control, set map[string]struct{}) bool {
	for _, identifier := range ControlIdentifiers(control) {
		if _, ok := set[identifier]; ok {
			return true
		}
	}
	return false
}

// FilterFrameworkControls applies the --skip-controls and --include-controls
// filters to frameworks and returns copies with the deselected controls
// removed. Include is a whitelist; skip is a blacklist and wins over include.
//
// The filter operates on whole controls, never on their rules. Rules are
// shared across controls in the policy library (for example
// non-root-containers backs both C-0013 and C-0211), so expressing "skip
// C-0211" as "exclude every rule C-0211 uses" would silently drop every other
// control built on those rules too, and "include C-0013" would strip C-0013's
// own rule while excluding its siblings. This mirrors
// policyhandler.excludeControls, which --exclude-controls uses.
//
// Matching is case-insensitive and accepts either identifier a control can be
// named by, mirroring --exclude-controls (see policyhandler/controlfilter.go's
// normalizeExclusions/markControlMatches): without this, a lowercase control ID
// or a CIS section number silently matches nothing, and since
// --include-controls treats "not in the include set" as "exclude", a single
// mistyped case produces a silently empty scan instead of the requested
// control.
//
// The returned frameworks share their Control values with the input but never
// its Controls backing arrays, so the caller's slice (which may be a cached
// policy set reused across scans) is left untouched.
func FilterFrameworkControls(frameworks []reporthandling.Framework, skip, include []string) ([]reporthandling.Framework, error) {
	if len(skip) == 0 && len(include) == 0 {
		return frameworks, nil
	}

	skipSet := make(map[string]struct{}, len(skip))
	for _, id := range skip {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			skipSet[id] = struct{}{}
		}
	}

	includeSet := make(map[string]struct{}, len(include))
	for _, id := range include {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			includeSet[id] = struct{}{}
		}
	}

	knownIDs := make(map[string]struct{})
	for _, fw := range frameworks {
		for i := range fw.Controls {
			for _, identifier := range ControlIdentifiers(&fw.Controls[i]) {
				knownIDs[identifier] = struct{}{}
			}
		}
	}

	for id := range skipSet {
		if _, ok := knownIDs[id]; !ok {
			logger.L().Warning("skip control not found in loaded policies", helpers.String("control", id))
		}
	}
	// include-controls is a whitelist: if the caller asked for specific
	// controls but none of them exist, failing open with 0 controls and
	// exit 0 breaks CI gates. Treat "no include matched" as a hard error,
	// mirroring policyhandler.excludeControls' errAllControlsExcluded.
	if len(includeSet) > 0 {
		matchedInclude := 0
		for id := range includeSet {
			if _, ok := knownIDs[id]; ok {
				matchedInclude++
			} else {
				logger.L().Warning("include control not found in loaded policies", helpers.String("control", id))
			}
		}
		if matchedInclude == 0 {
			return nil, ErrIncludeControlsNoMatch
		}
	}

	filtered := make([]reporthandling.Framework, 0, len(frameworks))
	remaining := 0
	for _, fw := range frameworks {
		kept := make([]reporthandling.Control, 0, len(fw.Controls))
		for i := range fw.Controls {
			control := &fw.Controls[i]
			if len(includeSet) > 0 && !ControlMatchesAny(control, includeSet) {
				continue
			}
			if ControlMatchesAny(control, skipSet) {
				continue
			}
			kept = append(kept, *control)
		}
		fw.Controls = kept
		remaining += len(kept)
		filtered = append(filtered, fw)
	}

	// Guard against a filter that leaves nothing to scan. This can happen
	// when --include-controls names only controls that are then removed by
	// --skip-controls, or when --skip-controls alone excludes every loaded
	// control. Mirroring excludeControls' remaining==0 check prevents a
	// 0-control, 0-failure, exit-0 scan that silently passes a CI gate.
	if remaining == 0 {
		return nil, ErrNoControlsAfterFilter
	}

	return filtered, nil
}

// EffectiveControlIDs returns the set of control IDs (ControlID values, as
// stored) selected by the --skip-controls/--include-controls flags. On any
// filter error it returns nil: the caller must fall back to the unfiltered
// set, since the evaluation phase re-applies the same filter and fails loudly
// there with the proper message.
func EffectiveControlIDs(frameworks []reporthandling.Framework, skip, include string) map[string]struct{} {
	filtered, err := FilterFrameworkControls(frameworks, SplitCommaList(skip), SplitCommaList(include))
	if err != nil {
		return nil
	}
	ids := make(map[string]struct{})
	for i := range filtered {
		for j := range filtered[i].Controls {
			ids[filtered[i].Controls[j].ControlID] = struct{}{}
		}
	}
	return ids
}
