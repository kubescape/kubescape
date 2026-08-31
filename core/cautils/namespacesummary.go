package cautils

import (
	"sort"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// clusterScopedNamespace buckets resources that carry no namespace
// (cluster-scoped kinds, or a manifest that omitted one) into a single named
// entry rather than dropping them from the rollup.
const clusterScopedNamespace = "<cluster-scoped>"

// NamespaceSummary is one namespace's compliance rollup. Every control in the
// scan's policy set is counted toward its score -- the same convention the
// cluster and framework scores already use -- so namespace scores stay
// directly comparable to one another and to the cluster-wide number.
type NamespaceSummary struct {
	Namespace       string  `json:"namespace"`
	ComplianceScore float32 `json:"complianceScore"`
	FailedControls  int     `json:"failedControls"`
	TotalControls   int     `json:"totalControls"`
	ResourceCount   int     `json:"resourceCount"`
}

// NamespaceSummaries is sorted ascending by ComplianceScore so the worst
// namespace leads.
type NamespaceSummaries []NamespaceSummary

// BuildNamespaceSummaries computes a per-namespace compliance rollup from the
// finalized control summaries.
//
// A control with no resource in a given namespace contributes 100 to that
// namespace's score, mirroring how a control with no resource anywhere
// already scores 100 at the cluster level (opa-utils
// ScoreUtil.GetControlComplianceScore). This keeps every namespace's score
// computed over the same TotalControls denominator, which is what makes them
// comparable to each other.
func BuildNamespaceSummaries(controls reportsummary.ControlSummaries, allResources map[string]workloadinterface.IMetadata) NamespaceSummaries {
	if len(controls) == 0 {
		return nil
	}

	namespaceOf := func(resourceID string) string {
		if resource, ok := allResources[resourceID]; ok && resource.GetNamespace() != "" {
			return resource.GetNamespace()
		}
		return clusterScopedNamespace
	}

	// perControlCounts[controlID][namespace] = [passed, total], computed once
	// per control up front so every namespace this scan actually touched is
	// known before any control's contribution is scored. A control with no
	// resource in a given namespace must still contribute 100 to it, and that
	// namespace must already exist in the result set for that to happen.
	perControlCounts := make(map[string]map[string][2]int, len(controls))
	resourcesByNamespace := make(map[string]map[string]struct{})
	for controlID, control := range controls {
		counts := make(map[string][2]int)
		for resourceID, status := range control.ResourceIDs.All() {
			namespace := namespaceOf(resourceID)
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

	totalControls := len(controls)
	summaries := make(NamespaceSummaries, 0, len(resourcesByNamespace))
	for namespace, resources := range resourcesByNamespace {
		var scoreSum float32
		var failedControls int
		for controlID := range controls {
			passed, total := 0, 0
			if c, ok := perControlCounts[controlID][namespace]; ok {
				passed, total = c[0], c[1]
			}
			score := float32(100)
			if total > 0 {
				score = (float32(passed) / float32(total)) * 100
			}
			scoreSum += score
			if score < 100 {
				failedControls++
			}
		}
		summaries = append(summaries, NamespaceSummary{
			Namespace:       namespace,
			ComplianceScore: scoreSum / float32(totalControls),
			FailedControls:  failedControls,
			TotalControls:   totalControls,
			ResourceCount:   len(resources),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].ComplianceScore != summaries[j].ComplianceScore {
			return summaries[i].ComplianceScore < summaries[j].ComplianceScore
		}
		return summaries[i].Namespace < summaries[j].Namespace
	})
	return summaries
}
