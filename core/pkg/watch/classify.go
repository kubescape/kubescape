package watch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
)

// Result is the comparison of a scan with the one before it. It is Compare's
// verdicts, which already refuse to call a finding new, resolved or unchanged
// when the scan cannot say, with two kinds of finding told apart that the diff
// engine reports as a removal and an addition. Every change the engine reports is
// in exactly one of the lists: none is dropped.
type Result struct {
	// New findings are on resources and controls the earlier scan was clear of.
	New []diff.ControlChange `json:"new,omitempty"`
	// Existing findings were in both scans, unchanged.
	Existing []diff.ControlChange `json:"existing,omitempty"`
	// Changed findings are in both scans and moved within their resource: the
	// evidence is of the same kind, from the same rule, at another path. See
	// ChangedFinding.
	Changed []ChangedFinding `json:"changed,omitempty"`
	// Resolved findings are gone from a resource that is still scanned, by a scan
	// that evaluated it in full.
	Resolved []diff.ControlChange `json:"resolved,omitempty"`
	// Removed findings are gone because their resource is: it is no longer in the
	// scan, which was complete enough to say so. They are not resolved, and they
	// are not findings on a resource the scan did not evaluate: those are
	// Incomparable.
	Removed []diff.ControlChange `json:"removed,omitempty"`
	// Renamed findings stayed with a resource that moved to another file. See
	// RenamedFinding.
	Renamed []RenamedFinding `json:"renamed,omitempty"`
	// Renames are the resources that moved, with the identities they had.
	Renames []Rename `json:"renames,omitempty"`
	// Incomparable findings cannot be classified from these two scans, for the
	// reason each carries: a coverage gap, an ambiguous resource, a control that
	// was not evaluated.
	Incomparable []diff.ControlChange `json:"incomparable,omitempty"`
	// Warnings say what the scans left unclear, such as resources that could not
	// be matched and renames that could not be established.
	Warnings []string `json:"warnings,omitempty"`
}

// ChangedFinding is a finding whose evidence moved: it was at Before in the
// earlier scan and is at After in the later one, the control, rule, kind of
// evidence and resource being the same. It is reported as one change only when
// each side has exactly one such finding; where several moved at once it is not
// known which went where, and they stay as resolved and new.
type ChangedFinding struct {
	Before diff.ControlChange `json:"before"`
	After  diff.ControlChange `json:"after"`
}

// RenamedFinding is a finding that was in the earlier scan on a resource that
// moved, and is in the later one on that resource, which is the finding's
// ResourceID there; From is the identity it had.
type RenamedFinding struct {
	Finding diff.ControlChange `json:"finding"`
	From    string             `json:"from"`
}

// Classify compares two scan reports in JSON form. See Result.
func Classify(baseJSON, headJSON []byte, options diff.Options) (*Result, error) {
	base, err := newSnapshot(baseJSON)
	if err != nil {
		return nil, fmt.Errorf("base report: %w", err)
	}
	head, err := newSnapshot(headJSON)
	if err != nil {
		return nil, fmt.Errorf("head report: %w", err)
	}
	return classify(base, head, options)
}

func classify(base, head *snapshot, options diff.Options) (*Result, error) {
	comparison, err := compareCanonical(base.report, head.report, options)
	if err != nil {
		return nil, err
	}
	changes := comparison.ChangeSet
	renames, notes := detectRenames(base, head)

	renamed, removed, added := pairRenamed(renames, comparison.Removed, changes.New)
	existing, resolved, added := pairEvidenceRenamed(renames, changes.Resolved, added)
	changed, resolved, added := pairChanged(renames, resolved, added)

	result := &Result{
		New:          added,
		Existing:     append(append([]diff.ControlChange(nil), changes.Unchanged...), existing...),
		Changed:      changed,
		Resolved:     resolved,
		Removed:      removed,
		Renamed:      renamed,
		Renames:      renames,
		Incomparable: changes.Incomparable,
		Warnings:     append(append([]string(nil), changes.Warnings...), notes...),
	}
	return result, nil
}

// fingerprint is what makes two findings the same finding on the same resource.
// An evidence resource is another resource the finding points at, so it is read
// through the renames: it may have moved as well.
func fingerprint(change diff.ControlChange, evidenceIdentity string) string {
	return strings.Join([]string{change.ControlID, change.RuleName, change.EvidenceType, change.Path, evidenceIdentity}, "\x00")
}

// pairRenamed pairs the findings that are removed with a resource that moved and
// the findings that are new on it. A finding on the moved resource that has a
// counterpart is the same finding and moved with it; one that has none stays
// removed or new, as it is a real difference.
func pairRenamed(renames []Rename, removed, added []diff.ControlChange) (renamed []RenamedFinding, stillRemoved, stillNew []diff.ControlChange) {
	if len(renames) == 0 {
		return nil, removed, added
	}
	moved := make(map[string]string, len(renames)) // earlier identity to later
	for _, rename := range renames {
		moved[rename.From] = rename.To
	}
	through := func(identity string) string {
		if to, ok := moved[identity]; ok {
			return to
		}
		return identity
	}

	removedUsed := make([]bool, len(removed))
	addedUsed := make([]bool, len(added))
	for _, rename := range renames {
		newOn := map[string]int{}
		for i, change := range added {
			if change.ResourceID == rename.To && !addedUsed[i] {
				newOn[fingerprint(change, change.EvidenceResourceID)] = i
			}
		}
		for i, change := range removed {
			if change.ResourceID != rename.From || removedUsed[i] {
				continue
			}
			j, ok := newOn[fingerprint(change, through(change.EvidenceResourceID))]
			if !ok {
				continue
			}
			delete(newOn, fingerprint(change, through(change.EvidenceResourceID)))
			removedUsed[i], addedUsed[j] = true, true
			renamed = append(renamed, RenamedFinding{Finding: added[j], From: rename.From})
		}
	}
	for i, change := range removed {
		if !removedUsed[i] {
			stillRemoved = append(stillRemoved, change)
		}
	}
	for i, change := range added {
		if !addedUsed[i] {
			stillNew = append(stillNew, change)
		}
	}
	sort.SliceStable(renamed, func(a, b int) bool {
		x, y := renamed[a], renamed[b]
		if x.From != y.From {
			return x.From < y.From
		}
		return lessChange(x.Finding, y.Finding)
	})
	return renamed, stillRemoved, stillNew
}

// pairEvidenceRenamed finds the findings that look resolved and new only because
// what they point at moved. A finding can name another resource as its evidence,
// and when that one is renamed the finding is no longer the same one by identity,
// though nothing about it changed: it is the same finding, so it is an existing
// one. The resource that has the finding did not move, or it would be a
// RenamedFinding.
func pairEvidenceRenamed(renames []Rename, resolved, added []diff.ControlChange) (existing, stillResolved, stillNew []diff.ControlChange) {
	if len(renames) == 0 {
		return nil, resolved, added
	}
	moved := make(map[string]string, len(renames))
	for _, rename := range renames {
		moved[rename.From] = rename.To
	}
	through := func(identity string) string {
		if to, ok := moved[identity]; ok {
			return to
		}
		return identity
	}

	type findingOn struct{ resourceID, fingerprint string }
	newBy := map[findingOn]int{}
	for i, change := range added {
		if change.EvidenceResourceID != "" {
			newBy[findingOn{change.ResourceID, fingerprint(change, change.EvidenceResourceID)}] = i
		}
	}
	resolvedUsed := make([]bool, len(resolved))
	addedUsed := make([]bool, len(added))
	for i, change := range resolved {
		if change.EvidenceResourceID == "" {
			continue
		}
		mapped := through(change.EvidenceResourceID)
		if mapped == change.EvidenceResourceID {
			continue // its evidence did not move, so it is a real difference
		}
		key := findingOn{change.ResourceID, fingerprint(change, mapped)}
		if j, ok := newBy[key]; ok {
			delete(newBy, key)
			resolvedUsed[i], addedUsed[j] = true, true
			existing = append(existing, added[j])
		}
	}
	for i, change := range resolved {
		if !resolvedUsed[i] {
			stillResolved = append(stillResolved, change)
		}
	}
	for i, change := range added {
		if !addedUsed[i] {
			stillNew = append(stillNew, change)
		}
	}
	sort.SliceStable(existing, func(a, b int) bool { return lessChange(existing[a], existing[b]) })
	return existing, stillResolved, stillNew
}

// changedGroup is what findings must share for one to be the other, moved.
type changedGroup struct {
	resourceID, controlID, ruleName, evidenceType, evidenceResourceID string
}

func groupOf(change diff.ControlChange, evidenceIdentity string) changedGroup {
	return changedGroup{change.ResourceID, change.ControlID, change.RuleName, change.EvidenceType, evidenceIdentity}
}

// pairChanged pairs a resolved finding with a new one on the same resource, of
// the same control, rule and kind of evidence, when each is the only one of its
// group: the evidence moved. Only findings that have a path can move. The earlier
// finding's evidence resource is read through the renames, as it may have moved
// to another file along with the finding.
func pairChanged(renames []Rename, resolved, added []diff.ControlChange) (changed []ChangedFinding, stillResolved, stillNew []diff.ControlChange) {
	moved := make(map[string]string, len(renames))
	for _, rename := range renames {
		moved[rename.From] = rename.To
	}
	resolvedBy := map[changedGroup][]int{}
	for i, change := range resolved {
		if change.Path != "" {
			evidence := change.EvidenceResourceID
			if to, ok := moved[evidence]; ok {
				evidence = to
			}
			group := groupOf(change, evidence)
			resolvedBy[group] = append(resolvedBy[group], i)
		}
	}
	addedBy := map[changedGroup][]int{}
	for i, change := range added {
		if change.Path != "" {
			group := groupOf(change, change.EvidenceResourceID)
			addedBy[group] = append(addedBy[group], i)
		}
	}

	resolvedUsed := make([]bool, len(resolved))
	addedUsed := make([]bool, len(added))
	for group, before := range resolvedBy {
		after := addedBy[group]
		if len(before) != 1 || len(after) != 1 {
			continue
		}
		resolvedUsed[before[0]], addedUsed[after[0]] = true, true
		changed = append(changed, ChangedFinding{Before: resolved[before[0]], After: added[after[0]]})
	}
	for i, change := range resolved {
		if !resolvedUsed[i] {
			stillResolved = append(stillResolved, change)
		}
	}
	for i, change := range added {
		if !addedUsed[i] {
			stillNew = append(stillNew, change)
		}
	}
	sort.SliceStable(changed, func(a, b int) bool { return lessChange(changed[a].After, changed[b].After) })
	return changed, stillResolved, stillNew
}

func lessChange(a, b diff.ControlChange) bool {
	switch {
	case a.ResourceID != b.ResourceID:
		return a.ResourceID < b.ResourceID
	case a.ControlID != b.ControlID:
		return a.ControlID < b.ControlID
	case a.RuleName != b.RuleName:
		return a.RuleName < b.RuleName
	case a.EvidenceType != b.EvidenceType:
		return a.EvidenceType < b.EvidenceType
	case a.Path != b.Path:
		return a.Path < b.Path
	}
	return a.EvidenceResourceID < b.EvidenceResourceID
}
