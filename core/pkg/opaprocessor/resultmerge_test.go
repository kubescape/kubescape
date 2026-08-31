package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func failedPath(path string) armotypes.PosturePaths {
	return armotypes.PosturePaths{ReviewPath: path}
}

func TestMergeAssociatedRule_StatusPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		existing apis.ScanningStatus
		incoming apis.ScanningStatus
		want     apis.ScanningStatus
	}{
		{name: "failure survives a later pass", existing: apis.StatusFailed, incoming: apis.StatusPassed, want: apis.StatusFailed},
		{name: "failure found later wins", existing: apis.StatusPassed, incoming: apis.StatusFailed, want: apis.StatusFailed},
		{name: "failure survives a later skip", existing: apis.StatusFailed, incoming: apis.StatusSkipped, want: apis.StatusFailed},
		{name: "skip is not downgraded by a pass", existing: apis.StatusSkipped, incoming: apis.StatusPassed, want: apis.StatusSkipped},
		{name: "skip downgrades a pass", existing: apis.StatusPassed, incoming: apis.StatusSkipped, want: apis.StatusSkipped},
		{name: "passes stay passed", existing: apis.StatusPassed, incoming: apis.StatusPassed, want: apis.StatusPassed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeAssociatedRule(
				&resourcesresults.ResourceAssociatedRule{Name: "rule", Status: tt.existing},
				&resourcesresults.ResourceAssociatedRule{Name: "rule", Status: tt.incoming},
			)
			assert.Equal(t, tt.want, got.Status)
		})
	}
}

func TestMergeAssociatedRule_AccumulatesFindings(t *testing.T) {
	got := mergeAssociatedRule(
		&resourcesresults.ResourceAssociatedRule{
			Name:                "rule",
			Status:              apis.StatusFailed,
			Paths:               []armotypes.PosturePaths{failedPath("from-ns-a")},
			RelatedResourcesIDs: []string{"related-1"},
		},
		&resourcesresults.ResourceAssociatedRule{
			Name:                "rule",
			Status:              apis.StatusFailed,
			Paths:               []armotypes.PosturePaths{failedPath("from-ns-b")},
			RelatedResourcesIDs: []string{"related-1", "related-2"},
		},
	)

	assert.Equal(t, []armotypes.PosturePaths{failedPath("from-ns-a"), failedPath("from-ns-b")}, got.Paths)
	assert.Equal(t, []string{"related-1", "related-2"}, got.RelatedResourcesIDs, "related resources must be a set")
}

// TestMergeAssociatedRule_DeduplicatesPaths covers a resident resource, which is
// evaluated once per namespace scope and reports the same path every time.
func TestMergeAssociatedRule_DeduplicatesPaths(t *testing.T) {
	merged := &resourcesresults.ResourceAssociatedRule{
		Name:   "rule",
		Status: apis.StatusFailed,
		Paths:  []armotypes.PosturePaths{failedPath("spec.hostNetwork")},
	}
	for range 3 {
		merged = mergeAssociatedRule(merged, &resourcesresults.ResourceAssociatedRule{
			Name:   "rule",
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{failedPath("spec.hostNetwork")},
		})
	}

	assert.Equal(t, []armotypes.PosturePaths{failedPath("spec.hostNetwork")}, merged.Paths)
}

func TestAppendUniquePaths(t *testing.T) {
	assert.Equal(t,
		[]armotypes.PosturePaths{failedPath("a"), failedPath("b")},
		appendUnique([]armotypes.PosturePaths{failedPath("a")}, []armotypes.PosturePaths{failedPath("a"), failedPath("b")}),
	)
	assert.Equal(t,
		[]armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: "a", Value: "1"}}, {FixPath: armotypes.FixPath{Path: "a", Value: "2"}}},
		appendUnique(
			[]armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: "a", Value: "1"}}},
			[]armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: "a", Value: "2"}}},
		),
		"paths differing only in fix value are distinct findings",
	)
}

// TestMergeAssociatedRule_KeepsSubStatus pins that a sub-status recorded by an
// earlier scope is not erased by a later, more definitive verdict that carries
// none — the previous in-place update had the same effect.
func TestMergeAssociatedRule_KeepsSubStatus(t *testing.T) {
	got := mergeAssociatedRule(
		&resourcesresults.ResourceAssociatedRule{Name: "rule", Status: apis.StatusSkipped, SubStatus: apis.SubStatusUnknown},
		&resourcesresults.ResourceAssociatedRule{Name: "rule", Status: apis.StatusFailed},
	)

	assert.Equal(t, apis.StatusFailed, got.Status)
	assert.Equal(t, apis.SubStatusUnknown, got.SubStatus)
}

func TestMergeAssociatedRule_NilOperands(t *testing.T) {
	rule := &resourcesresults.ResourceAssociatedRule{Name: "rule", Status: apis.StatusFailed}

	assert.Equal(t, rule, mergeAssociatedRule(nil, rule))
	assert.Equal(t, rule, mergeAssociatedRule(rule, nil))
	assert.Nil(t, mergeAssociatedRule(nil, nil))
}

func TestMergeAssociatedRules_MatchesByNameAndKeepsOrder(t *testing.T) {
	got := mergeAssociatedRules(
		[]resourcesresults.ResourceAssociatedRule{
			{Name: "rule-a", Status: apis.StatusPassed},
			{Name: "rule-b", Status: apis.StatusPassed},
		},
		[]resourcesresults.ResourceAssociatedRule{
			{Name: "rule-b", Status: apis.StatusFailed},
			{Name: "rule-c", Status: apis.StatusFailed},
		},
	)

	require.Len(t, got, 3)
	assert.Equal(t, "rule-a", got[0].Name)
	assert.Equal(t, apis.StatusPassed, got[0].Status)
	assert.Equal(t, "rule-b", got[1].Name)
	assert.Equal(t, apis.StatusFailed, got[1].Status, "same rule from another scope must merge, not duplicate")
	assert.Equal(t, "rule-c", got[2].Name)
}

func TestMergeAssociatedControls_MergesSameControl(t *testing.T) {
	existing := []resourcesresults.ResourceAssociatedControl{
		{ControlID: "C-0001", ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule", Status: apis.StatusPassed}}},
	}
	incoming := resourcesresults.ResourceAssociatedControl{
		ControlID:               "C-0001",
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule", Status: apis.StatusFailed}},
	}

	got := mergeAssociatedControls(existing, incoming, nil)

	require.Len(t, got, 1, "a control evaluated in several scopes must not be duplicated")
	require.Len(t, got[0].ResourceAssociatedRules, 1)
	assert.Equal(t, apis.StatusFailed, got[0].ResourceAssociatedRules[0].Status)
}

func TestMergeAssociatedControls_AppendsDifferentControl(t *testing.T) {
	existing := []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0001"}}
	incoming := resourcesresults.ResourceAssociatedControl{ControlID: "C-0002"}

	got := mergeAssociatedControls(existing, incoming, nil)

	require.Len(t, got, 2)
	assert.Equal(t, "C-0002", got[1].ControlID)
}

func TestAppendUnique(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, appendUnique([]string{"a", "b"}, []string{"b", "c", "c"}))
	assert.Equal(t, []string{"a"}, appendUnique([]string{"a"}, nil))
	assert.Equal(t, []string{"a"}, appendUnique(nil, []string{"a", "a"}))
}
