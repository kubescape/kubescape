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

	// A result that was set aside stays in the compared reports under an ID of
	// its own, so its findings land here instead of vanishing.
	withheld := map[string]string{}
	for id, reason := range base.Withheld {
		withheld[id] = "base scan: " + reason
	}
	for id, reason := range head.Withheld {
		if previous, both := withheld[id]; both {
			reason = previous + "; head scan: " + reason
		} else {
			reason = "head scan: " + reason
		}
		withheld[id] = reason
	}

	comparison := &Comparison{ChangeSet: changeSet}
	// reclassify moves to Incomparable the changes that cannot be trusted:
	// those on an ambiguous or set-aside resource, and those whose control also
	// has a finding, in the other report, on a resource that could not be
	// identified and so may be the very same finding.
	reclassify := func(changes []diff.ControlChange, unidentified map[string]struct{}, side string) (kept []diff.ControlChange) {
		for _, change := range changes {
			reason, incomparable := reasons[change.ResourceID]
			if !incomparable {
				reason, incomparable = withheld[change.ResourceID]
			}
			if _, maybeSame := unidentified[change.ControlID]; !incomparable && maybeSame {
				reason = side + " scan has a finding for this control on a resource it could not identify, which may be this one"
				incomparable = true
			}
			if incomparable {
				change.Reason = reason
				changeSet.Incomparable = append(changeSet.Incomparable, change)
				continue
			}
			kept = append(kept, change)
		}
		return kept
	}
	// A new finding may be a base finding the base scan could not place, and a
	// resolved one may be a head finding the head scan could not place.
	changeSet.New = reclassify(changeSet.New, base.UnidentifiedControls, "base")
	changeSet.Unchanged = reclassify(changeSet.Unchanged, nil, "")
	resolved := reclassify(changeSet.Resolved, head.UnidentifiedControls, "head")
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
