package pss

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NamespaceResult aggregates PSS evaluation results across all workloads in
// a namespace. It is the shared result type used by both the CLI and MCP tool.
type NamespaceResult struct {
	// Namespace is the evaluated namespace (empty for local file scans).
	Namespace string

	// TargetLevel is the PSS level workloads were evaluated against.
	TargetLevel Level

	// TotalWorkloads is the number of workloads evaluated (including unevaluated).
	TotalWorkloads int

	// PassingWorkloads is the count of workloads that pass at the target level.
	PassingWorkloads int

	// FailingWorkloads is the count of workloads that have violations at the target level.
	FailingWorkloads int

	// UnevaluatedWorkloads is the count of workloads that could not be evaluated
	// (e.g., PodSpec extraction failed).
	UnevaluatedWorkloads int

	// CurrentEffectiveLevel is the strictest level at which every evaluated
	// workload in the namespace still passes. If even Baseline fails for some
	// workload, this is Privileged.
	CurrentEffectiveLevel Level

	// Results contains WorkloadResult for every evaluated workload, both
	// passing and failing, sorted by Kind then Name.
	Results []WorkloadResult

	// DecodeWarnings contains human-readable messages for workloads that
	// could not be evaluated (PodSpec extraction or decode errors).
	DecodeWarnings []string
}

// FailingResults returns only the WorkloadResults that have violations.
func (nr *NamespaceResult) FailingResults() []WorkloadResult {
	var failing []WorkloadResult
	for _, r := range nr.Results {
		if len(r.Violations) > 0 {
			failing = append(failing, r)
		}
	}
	return failing
}

// PassingResults returns only the WorkloadResults that have no violations.
func (nr *NamespaceResult) PassingResults() []WorkloadResult {
	var passing []WorkloadResult
	for _, r := range nr.Results {
		if len(r.Violations) == 0 {
			passing = append(passing, r)
		}
	}
	return passing
}

// HasFailures returns true if any workload has violations at the target level.
func (nr *NamespaceResult) HasFailures() bool {
	return nr.FailingWorkloads > 0
}

// Aggregate evaluates a slice of unstructured workloads against the given
// target PSS level and produces a NamespaceResult. Workloads whose PodSpec
// cannot be extracted are counted as unevaluated and recorded in DecodeWarnings.
//
// The results are sorted by Kind then Name for stable, deterministic output.
func Aggregate(namespace string, workloads []unstructured.Unstructured, targetLevel Level) NamespaceResult {
	nr := NamespaceResult{
		Namespace:             namespace,
		TargetLevel:           targetLevel,
		TotalWorkloads:        len(workloads),
		CurrentEffectiveLevel: Restricted,
		Results:               make([]WorkloadResult, 0, len(workloads)),
	}

	for _, item := range workloads {
		kind := item.GetKind()
		name := item.GetName()

		res, err := WorkloadResultFromUnstructured(kind, name, namespace, item.Object, targetLevel)
		if err != nil {
			nr.DecodeWarnings = append(nr.DecodeWarnings, fmt.Sprintf("%s/%s: %v", kind, name, err))
			nr.UnevaluatedWorkloads++
			continue
		}

		if res.PassesAt < nr.CurrentEffectiveLevel {
			nr.CurrentEffectiveLevel = res.PassesAt
		}

		if len(res.Violations) > 0 {
			nr.FailingWorkloads++
		} else {
			nr.PassingWorkloads++
		}

		nr.Results = append(nr.Results, res)
	}

	// Sort by Kind then Name for deterministic output.
	sort.Slice(nr.Results, func(i, j int) bool {
		if nr.Results[i].Kind != nr.Results[j].Kind {
			return nr.Results[i].Kind < nr.Results[j].Kind
		}
		return nr.Results[i].Name < nr.Results[j].Name
	})

	return nr
}

// ToMap converts NamespaceResult to the JSON-compatible map structure expected
// by the MCP server and backwards-compatible consumers.
func (nr *NamespaceResult) ToMap() map[string]any {
	summary := map[string]any{
		"total_workloads":         nr.TotalWorkloads,
		"passing":                 nr.PassingWorkloads,
		"failing":                 nr.FailingWorkloads,
		"current_effective_level": nr.CurrentEffectiveLevel.String(),
	}
	if nr.UnevaluatedWorkloads > 0 {
		summary["unevaluated"] = nr.UnevaluatedWorkloads
		summary["current_effective_level_complete"] = false
	}

	failingWorkloads := make([]map[string]any, 0, len(nr.FailingResults()))
	for _, res := range nr.FailingResults() {
		vSummaries := make([]map[string]any, 0, len(res.Violations))
		for _, v := range res.Violations {
			vSummaries = append(vSummaries, map[string]any{
				"check":       v.Check,
				"container":   v.Container,
				"level":       v.Level.String(),
				"description": v.Description,
			})
		}
		failingWorkloads = append(failingWorkloads, map[string]any{
			"kind":       res.Kind,
			"name":       res.Name,
			"violations": vSummaries,
			"passes_at":  res.PassesAt.String(),
		})
	}

	result := map[string]any{
		"namespace":         nr.Namespace,
		"target_level":      nr.TargetLevel.String(),
		"summary":           summary,
		"failing_workloads": failingWorkloads,
	}

	if len(nr.DecodeWarnings) > 0 {
		result["decode_warnings"] = nr.DecodeWarnings
	}

	return result
}
