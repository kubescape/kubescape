package mapreconcile

import (
	"fmt"

	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
)

// MutationSummary is one Mutation from a matched policy, reported verbatim --
// see the package doc for why this is not evaluated.
type MutationSummary struct {
	PatchType  admissionregistrationv1alpha1.PatchType
	Expression string
}

// MatchedPolicy is one MutatingAdmissionPolicy (bound by one binding) whose
// matchConstraints and matchResources together cover a queried object.
type MatchedPolicy struct {
	PolicyName  string
	BindingName string
	Mutations   []MutationSummary
	// FailurePolicy is the policy's own spec.failurePolicy (defaults to Fail
	// when unset, the same default the API server applies), included because
	// it changes what "this policy matches" means in practice: Fail means a
	// broken mutation blocks admission of the object entirely, not just skips
	// the mutation.
	FailurePolicy admissionregistrationv1alpha1.FailurePolicyType
	// HasParams is true when the policy declares a paramKind. This package
	// does not resolve paramRef, so a matched policy with HasParams true may
	// in fact be misconfigured (missing/invalid params) and skipped or
	// denied at admission depending on FailurePolicy -- the match reported
	// here is necessary but not sufficient in that case.
	HasParams bool
	// Determinable is false when this policy's match could not be confirmed
	// from the data available (see compiledMatchResources.matches): the
	// caller should treat MatchedPolicy as "might apply," not "does apply."
	Determinable bool
}

// compiledPolicy pre-parses one MutatingAdmissionPolicy's matchConstraints,
// and every binding that names it, once.
type compiledPolicy struct {
	policy          admissionregistrationv1alpha1.MutatingAdmissionPolicy
	matchConstraint *compiledMatchResources
	bindings        []compiledBinding
}

type compiledBinding struct {
	binding       admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding
	matchResource *compiledMatchResources // nil matchResources on a binding constrains nothing further
}

// Index indexes a cluster's MutatingAdmissionPolicy and
// MutatingAdmissionPolicyBinding objects for repeated match queries against
// the same snapshot.
type Index struct {
	policies []*compiledPolicy
}

// NewIndex builds an Index from a cluster's (or a query's) collected
// MutatingAdmissionPolicy and MutatingAdmissionPolicyBinding objects. A
// policy or binding with an unparseable selector is skipped, with its error
// appended to errs, rather than one malformed object hiding every other
// policy's match result -- see Collect's doc comment for why silently
// dropping is the wrong default here.
func NewIndex(policies []admissionregistrationv1alpha1.MutatingAdmissionPolicy, bindings []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding) (idx *Index, errs []error) {
	idx = &Index{}

	bindingsByPolicy := make(map[string][]admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding, len(bindings))
	for _, b := range bindings {
		bindingsByPolicy[b.Spec.PolicyName] = append(bindingsByPolicy[b.Spec.PolicyName], b)
	}

	for _, p := range policies {
		mc, err := compileMatchResources(p.Spec.MatchConstraints)
		if err != nil {
			errs = append(errs, fmt.Errorf("MutatingAdmissionPolicy %s: unparseable matchConstraints, skipped: %w", p.Name, err))
			continue
		}

		cp := &compiledPolicy{policy: p, matchConstraint: mc}
		for _, b := range bindingsByPolicy[p.Name] {
			var cmr *compiledMatchResources
			if b.Spec.MatchResources != nil {
				compiled, err := compileMatchResources(b.Spec.MatchResources)
				if err != nil {
					errs = append(errs, fmt.Errorf("MutatingAdmissionPolicyBinding %s: unparseable matchResources, skipped: %w", b.Name, err))
					continue
				}
				cmr = compiled
			}
			cp.bindings = append(cp.bindings, compiledBinding{binding: b, matchResource: cmr})
		}
		idx.policies = append(idx.policies, cp)
	}

	return idx, errs
}

// Matches reports every (policy, binding) pair whose matchConstraints and
// matchResources both cover obj. A policy with no binding at all never
// mutates anything -- MutatingAdmissionPolicy, like ValidatingAdmissionPolicy,
// takes effect only once bound -- so it is silently excluded rather than
// reported as an unbound near-miss.
func (idx *Index) Matches(obj ObjectInfo) []MatchedPolicy {
	var out []MatchedPolicy
	for _, cp := range idx.policies {
		policyMatched, policyDeterminable := cp.matchConstraint.matches(obj)
		if policyDeterminable && !policyMatched {
			continue
		}

		for _, cb := range cp.bindings {
			determinable := policyDeterminable
			matched := policyMatched

			if cb.matchResource != nil {
				bMatched, bDeterminable := cb.matchResource.matches(obj)
				determinable = determinable && bDeterminable
				matched = matched && bMatched
				if bDeterminable && !bMatched {
					// The binding confidently excludes obj regardless of what
					// the policy side could resolve.
					continue
				}
			}
			if determinable && !matched {
				continue
			}

			out = append(out, MatchedPolicy{
				PolicyName:    cp.policy.Name,
				BindingName:   cb.binding.Name,
				Mutations:     mutationSummaries(cp.policy.Spec.Mutations),
				FailurePolicy: failurePolicyOrDefault(cp.policy.Spec.FailurePolicy),
				HasParams:     cp.policy.Spec.ParamKind != nil,
				Determinable:  determinable,
			})
		}
	}
	return out
}

func mutationSummaries(mutations []admissionregistrationv1alpha1.Mutation) []MutationSummary {
	out := make([]MutationSummary, 0, len(mutations))
	for _, m := range mutations {
		s := MutationSummary{PatchType: m.PatchType}
		switch m.PatchType {
		case admissionregistrationv1alpha1.PatchTypeApplyConfiguration:
			if m.ApplyConfiguration != nil {
				s.Expression = m.ApplyConfiguration.Expression
			}
		case admissionregistrationv1alpha1.PatchTypeJSONPatch:
			if m.JSONPatch != nil {
				s.Expression = m.JSONPatch.Expression
			}
		}
		out = append(out, s)
	}
	return out
}

func failurePolicyOrDefault(fp *admissionregistrationv1alpha1.FailurePolicyType) admissionregistrationv1alpha1.FailurePolicyType {
	if fp == nil {
		return admissionregistrationv1alpha1.Fail
	}
	return *fp
}
