package opaprocessor

import (
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// Merging per-scope verdicts.
//
// A resident resource is part of the input of every scope, so the same
// (resource, rule) pair is assessed once per scope and the verdicts must be
// combined. The rules below reproduce, across scopes, what the previous
// rule-outer/namespace-inner loop did while writing into a single map:
//
//   - status precedence is failed > skipped > passed: a resource that failed
//     in any scope failed, and an evaluation error in any scope downgrades a
//     pass to skipped but never overrides a failure;
//   - paths accumulate as a set, because a rule can report a different failed
//     path per scope but reports the same path in every scope for a resident
//     resource;
//   - related resource IDs accumulate as a set, preserving first-seen order.

// ruleStatusRank orders statuses by how definitive they are.
func ruleStatusRank(status apis.ScanningStatus) int {
	switch status {
	case apis.StatusFailed:
		return 3
	case apis.StatusSkipped:
		return 2
	case apis.StatusPassed:
		return 1
	default:
		return 0
	}
}

// mergeAssociatedRule combines the verdicts a single rule reached for one
// resource in two different scopes. Either side may be nil.
func mergeAssociatedRule(existing, incoming *resourcesresults.ResourceAssociatedRule) *resourcesresults.ResourceAssociatedRule {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	if ruleStatusRank(incoming.Status) > ruleStatusRank(existing.Status) {
		existing.Status = incoming.Status
		// the failing path only sets Status, leaving a sub-status recorded by
		// an earlier scope in place
		if incoming.SubStatus != "" {
			existing.SubStatus = incoming.SubStatus
		}
	}
	if existing.Name == "" {
		existing.Name = incoming.Name
	}
	if existing.ControlConfigurations == nil {
		existing.ControlConfigurations = incoming.ControlConfigurations
	}

	existing.Paths = appendUnique(existing.Paths, incoming.Paths)
	existing.RelatedResourcesIDs = appendUnique(existing.RelatedResourcesIDs, incoming.RelatedResourcesIDs)

	return existing
}

// mergeAssociatedRules combines two per-scope rule lists of the same control,
// matching rules by name and preserving the order in which they first appeared.
func mergeAssociatedRules(existing, incoming []resourcesresults.ResourceAssociatedRule) []resourcesresults.ResourceAssociatedRule {
	if len(existing) == 0 {
		return incoming
	}

	index := make(map[string]int, len(existing))
	for i := range existing {
		index[existing[i].Name] = i
	}

	for i := range incoming {
		at, ok := index[incoming[i].Name]
		if !ok {
			index[incoming[i].Name] = len(existing)
			existing = append(existing, incoming[i])
			continue
		}
		merged := mergeAssociatedRule(&existing[at], &incoming[i])
		existing[at] = *merged
	}

	return existing
}

// mergeAssociatedControls merges a control result produced for one scope into
// the results accumulated for a resource so far. The control's status is
// recomputed from the merged rule set, so a failure found in any scope is
// reflected even if a later scope passed.
func mergeAssociatedControls(existing []resourcesresults.ResourceAssociatedControl, incoming resourcesresults.ResourceAssociatedControl, policies *cautils.Policies) []resourcesresults.ResourceAssociatedControl {
	for i := range existing {
		if existing[i].ControlID != incoming.ControlID {
			continue
		}
		existing[i].ResourceAssociatedRules = mergeAssociatedRules(existing[i].ResourceAssociatedRules, incoming.ResourceAssociatedRules)
		if policies != nil {
			if control, ok := policies.Controls[incoming.ControlID]; ok {
				existing[i].SetStatus(control)
			}
		}
		return existing
	}

	return append(existing, incoming)
}

// appendUnique appends the values of incoming that existing does not already
// hold, preserving order. One pass over each slice, so merging a resident
// resource across many scopes stays linear in the number of distinct values.
func appendUnique[T comparable](existing, incoming []T) []T {
	if len(incoming) == 0 {
		return existing
	}

	seen := make(map[T]struct{}, len(existing)+len(incoming))
	for _, value := range existing {
		seen[value] = struct{}{}
	}
	for _, value := range incoming {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		existing = append(existing, value)
	}

	return existing
}
