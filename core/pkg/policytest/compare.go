package policytest

import (
	"encoding/json"
	"sort"

	"github.com/google/go-cmp/cmp"
	"github.com/kubescape/opa-utils/reporthandling"
)

// Compare reports whether got matches want, ignoring the order of the
// response slice and the order within each response's path lists (the
// evaluator does not guarantee either). It returns an empty diff on a match.
func Compare(got, want []reporthandling.RuleResponse) string {
	normGot := normalize(got)
	normWant := normalize(want)
	return cmp.Diff(normWant, normGot)
}

func normalize(responses []reporthandling.RuleResponse) []reporthandling.RuleResponse {
	out := make([]reporthandling.RuleResponse, len(responses))
	copy(out, responses)
	for i := range out {
		sort.Strings(out[i].FailedPaths)
		sort.Strings(out[i].ReviewPaths)
		sort.Strings(out[i].DeletePaths)
		sort.Slice(out[i].FixPaths, func(a, b int) bool {
			return out[i].FixPaths[a].Path < out[i].FixPaths[b].Path
		})
		// A nil slice and an empty slice both mean "no k8s objects"; the
		// evaluator and expected.json fixtures don't agree on which one they
		// use, so treat them as equal rather than flagging a false diff.
		if len(out[i].AlertObject.K8SApiObjects) == 0 {
			out[i].AlertObject.K8SApiObjects = nil
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return sortKey(out[i]) < sortKey(out[j])
	})
	return out
}

// sortKey serializes the entire normalized response to JSON. Two responses
// only produce the same key if they are equal in every field cmp.Diff
// compares, so this is a true total order: unlike picking a handful of
// fields by hand, it cannot silently miss one and let unrelated responses
// tie, which would make their relative order depend on sort.Slice's
// unspecified tie-breaking instead of their actual content.
func sortKey(r reporthandling.RuleResponse) string {
	b, err := json.Marshal(r)
	if err != nil {
		// RuleResponse holds only JSON-safe data (strings, slices, maps of
		// primitives), so Marshal cannot fail in practice; AlertMessage is a
		// reasonable, if weaker, fallback key if it somehow did.
		return r.AlertMessage
	}
	return string(b)
}
