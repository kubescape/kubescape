package cautils

import (
	"sort"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// ClusterScopedNamespace buckets resources that carry no namespace
// (cluster-scoped kinds, or a manifest that omitted one) into a single named
// entry rather than dropping them from the rollup. It is not a real
// Kubernetes namespace, so callers must not treat it as user data (the
// anonymizer skips it for that reason).
const ClusterScopedNamespace = "<cluster-scoped>"

// NamespaceSummary is one namespace's compliance rollup. Every control in the
// scan's policy set is counted toward its score -- the same convention the
// cluster and framework scores already use -- so namespace scores stay
// directly comparable to one another and to the cluster-wide number.
type NamespaceSummary struct {
	Namespace       string  `json:"namespace"`
	ComplianceScore float32 `json:"complianceScore"`
	// NonCompliantControls counts controls that did not score a clean 100 in
	// this namespace. It is not the same as apis.StatusFailed: a control that
	// is merely partially passing, or entirely skipped/action-required here,
	// also counts, so this figure does not reconcile with the cluster
	// summary's failed-control counter.
	NonCompliantControls int `json:"nonCompliantControls"`
	TotalControls        int `json:"totalControls"`
	ResourceCount        int `json:"resourceCount"`
}

// NamespaceSummaries is sorted ascending by ComplianceScore so the worst
// namespace leads.
type NamespaceSummaries []NamespaceSummary

// BuildNamespaceSummaries computes a per-namespace compliance rollup from the
// finalized control summaries. It must run after the score wrapper has set
// ControlSummary.ComplianceScore for every control (see the callers in
// processorhandler.go): a control with no resource in a given namespace
// contributes that already-computed score to the namespace, whatever it is,
// rather than assuming 100. This matters because opa-utils'
// GetControlComplianceScore only returns 100 for a zero-resource control that
// is also Passed (a control the cluster genuinely never needed); a control
// that could not be evaluated (RBAC-restricted collection, a timeout) is
// zero-resource too but scores 0, and namespaces must inherit that same 0,
// not a free 100, to stay comparable to the cluster number sitting next to
// them in the same report.
func BuildNamespaceSummaries(controls reportsummary.ControlSummaries, allResources map[string]workloadinterface.IMetadata) NamespaceSummaries {
	if len(controls) == 0 {
		return nil
	}

	namespaceOf := func(resourceID string) string {
		if resource, ok := allResources[resourceID]; ok && resource.GetNamespace() != "" {
			return resource.GetNamespace()
		}
		return ClusterScopedNamespace
	}

	// resourcesByNamespace is seeded from every scanned resource, not just
	// ones a control matched, so a namespace holding only resources no
	// control examines still gets a summary instead of being silently absent
	// from the rollup.
	resourcesByNamespace := make(map[string]map[string]struct{})
	for resourceID := range allResources {
		namespace := namespaceOf(resourceID)
		if resourcesByNamespace[namespace] == nil {
			resourcesByNamespace[namespace] = make(map[string]struct{})
		}
		resourcesByNamespace[namespace][resourceID] = struct{}{}
	}

	// controlIDs is sorted once and reused for every namespace below, so
	// scoreSum always accumulates in the same order across runs. float32
	// addition is not associative, and ranging a map iterates in randomized
	// order, so without this the same input could produce a ComplianceScore
	// that differs by a ULP between two runs -- and with it, defeat the exact
	// tie-break the final sort below relies on.
	controlIDs := make([]string, 0, len(controls))
	for controlID := range controls {
		controlIDs = append(controlIDs, controlID)
	}
	sort.Strings(controlIDs)

	// perControlCounts[controlID][namespace] = [passed, total], computed once
	// per control up front so every namespace this scan actually touched is
	// known before any control's contribution is scored.
	perControlCounts := make(map[string]map[string][2]int, len(controls))
	for _, controlID := range controlIDs {
		control := controls[controlID]
		counts := make(map[string][2]int)
		for resourceID, status := range control.ResourceIDs.All() {
			namespace := namespaceOf(resourceID)
			// Usually already seeded from allResources above; kept here too
			// so a control's resource ID that is missing from allResources
			// still lands in the rollup instead of being silently dropped.
			if resourcesByNamespace[namespace] == nil {
				resourcesByNamespace[namespace] = make(map[string]struct{})
			}
			resourcesByNamespace[namespace][resourceID] = struct{}{}

			c := counts[namespace]
			c[1]++
			if status == apis.StatusPassed {
				c[0]++
			}
			counts[namespace] = c
		}
		perControlCounts[controlID] = counts
	}

	namespaces := make([]string, 0, len(resourcesByNamespace))
	for namespace := range resourcesByNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	totalControls := len(controls)
	summaries := make(NamespaceSummaries, 0, len(namespaces))
	for _, namespace := range namespaces {
		var scoreSum float64
		var nonCompliantControls int
		for _, controlID := range controlIDs {
			var score float32
			if c, ok := perControlCounts[controlID][namespace]; ok && c[1] > 0 {
				passed, total := c[0], c[1]
				score = (float32(passed) / float32(total)) * 100
			} else {
				// No resource of this control's in this namespace: inherit
				// the control's own cluster-computed score rather than
				// assuming 100 (see the function doc comment).
				control := controls[controlID]
				score = control.GetComplianceScore()
				if score < 0 {
					// Defensive fallback for a caller that runs this before
					// the score wrapper: mirrors opa-utils' own zero-resource
					// default so behavior degrades to the old approximation
					// rather than a negative score.
					score = 100
				}
			}
			scoreSum += float64(score)
			if score < 100 {
				nonCompliantControls++
			}
		}
		summaries = append(summaries, NamespaceSummary{
			Namespace:            namespace,
			ComplianceScore:      float32(scoreSum / float64(totalControls)),
			NonCompliantControls: nonCompliantControls,
			TotalControls:        totalControls,
			ResourceCount:        len(resourcesByNamespace[namespace]),
		})
	}

	// namespaces was built in sorted order, so a stable sort by score alone
	// keeps ties in that same alphabetical order without a second comparison.
	sort.SliceStable(summaries, func(i, j int) bool {
		return summaries[i].ComplianceScore < summaries[j].ComplianceScore
	})
	return summaries
}
