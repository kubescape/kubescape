package policytest

import (
	"sort"
	"strings"

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
		if out[i].AlertMessage != out[j].AlertMessage {
			return out[i].AlertMessage < out[j].AlertMessage
		}
		return sortKey(out[i]) < sortKey(out[j])
	})
	return out
}

// sortKey joins a response's (already sorted) path lists into a single
// string, so two responses that share an AlertMessage but differ in their
// failed/review/delete paths still sort deterministically instead of
// depending on their input order.
func sortKey(r reporthandling.RuleResponse) string {
	var b strings.Builder
	b.WriteString(strings.Join(r.FailedPaths, ","))
	b.WriteByte('|')
	b.WriteString(strings.Join(r.ReviewPaths, ","))
	b.WriteByte('|')
	b.WriteString(strings.Join(r.DeletePaths, ","))
	return b.String()
}
