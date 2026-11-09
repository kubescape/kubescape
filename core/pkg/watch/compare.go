package watch

import (
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
)

// Comparison is the outcome of comparing two scans of the same manifests.
type Comparison struct {
	// ChangeSet holds the new, resolved, unchanged and incomparable findings.
	// Resolved holds only findings whose resource is still present.
	ChangeSet *diff.ChangeSet
	// Removed holds findings that disappeared because their resource is no
	// longer in the scan, as opposed to being fixed. The diff engine has
	// already judged scan coverage complete enough to call these resolved.
	Removed []diff.ControlChange
}

// Compare compares two scan reports in JSON form by stable resource identity.
// It never reports a finding as new, resolved or unchanged when its resource
// could not be matched safely: those findings are Incomparable, with the
// reason, and the identities are listed in the change set's Warnings.
func Compare(baseJSON, headJSON []byte, options diff.Options) (*Comparison, error) {
	base, err := Canonicalize(baseJSON)
	if err != nil {
		return nil, fmt.Errorf("base report: %w", err)
	}
	head, err := Canonicalize(headJSON)
	if err != nil {
		return nil, fmt.Errorf("head report: %w", err)
	}

	changeSet, err := diff.ComputeFromJSON(base.JSON, head.JSON, options)
	if err != nil {
		return nil, err
	}

	reasons := map[string]string{}
	for identity, reason := range base.Ambiguous {
		reasons[identity] = "base scan: " + reason
	}
	for identity, reason := range head.Ambiguous {
		if previous, both := reasons[identity]; both {
			reason = previous + "; head scan: " + reason
		} else {
			reason = "head scan: " + reason
		}
		reasons[identity] = reason
	}
	for _, identity := range sortedKeys(reasons) {
		changeSet.Warnings = append(changeSet.Warnings, fmt.Sprintf("resource %q cannot be compared: %s", identity, reasons[identity]))
	}

	comparison := &Comparison{ChangeSet: changeSet}
	reclassify := func(changes []diff.ControlChange) (kept []diff.ControlChange) {
		for _, change := range changes {
			if reason, ambiguous := reasons[change.ResourceID]; ambiguous {
				change.Reason = reason
				changeSet.Incomparable = append(changeSet.Incomparable, change)
				continue
			}
			kept = append(kept, change)
		}
		return kept
	}
	changeSet.New = reclassify(changeSet.New)
	changeSet.Unchanged = reclassify(changeSet.Unchanged)
	resolved := reclassify(changeSet.Resolved)
	changeSet.Resolved = nil
	for _, change := range resolved {
		if _, present := head.Resources[change.ResourceID]; present {
			changeSet.Resolved = append(changeSet.Resolved, change)
		} else {
			comparison.Removed = append(comparison.Removed, change)
		}
	}
	return comparison, nil
}
