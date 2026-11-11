package remediationverify

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	resA = "path=111/api=apps/v1/default/Deployment/a"
	resB = "path=222/api=apps/v1/default/Deployment/b"
)

func control(id string, status apis.ScanningStatus, sub apis.ScanningSubStatus) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: id,
		Status:    apis.StatusInfo{InnerStatus: status, SubStatus: sub},
	}
}

func passed(id string) resourcesresults.ResourceAssociatedControl {
	return control(id, apis.StatusPassed, apis.SubStatusUnknown)
}

func failed(id string) resourcesresults.ResourceAssociatedControl {
	return control(id, apis.StatusFailed, apis.SubStatusUnknown)
}

func result(resourceID string, controls ...resourcesresults.ResourceAssociatedControl) resourcesresults.Result {
	return resourcesresults.Result{ResourceID: resourceID, AssociatedControls: controls}
}

// complete is the coverage of a scan that finished with nothing missing.
func complete() *cautils.ScanCoverage {
	return &cautils.ScanCoverage{EvaluatedControls: 1, TotalControls: 1}
}

func classifyOne(results []resourcesresults.Result, coverage *cautils.ScanCoverage, degraded bool, item Item) Result {
	resp := Classify(&reporthandlingv2.PostureReport{Results: results}, coverage, degraded, []Item{item})
	return resp.Results[0]
}

func TestClassifyVerdicts(t *testing.T) {
	tests := []struct {
		name        string
		results     []resourcesresults.Result
		coverage    *cautils.ScanCoverage
		degraded    bool
		item        Item
		wantVerdict string
		wantReason  string
	}{
		{
			name:        "passed with complete coverage is resolved",
			results:     []resourcesresults.Result{result(resA, passed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictResolved, wantReason: ReasonControlPassed,
		},
		{
			name:        "failed is still failing",
			results:     []resourcesresults.Result{result(resA, failed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictStillFailing, wantReason: ReasonControlFailed,
		},
		{
			name:        "a still failing control is reported even when the scan is degraded",
			results:     []resourcesresults.Result{result(resA, failed("C-0017"))},
			coverage:    &cautils.ScanCoverage{Degraded: true},
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictStillFailing, wantReason: ReasonControlFailed,
		},
		{
			name:        "control ids match regardless of case and space",
			results:     []resourcesresults.Result{result(resA, passed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, " c-0017 "},
			wantVerdict: VerdictResolved, wantReason: ReasonControlPassed,
		},
		{
			name:        "an item with no resource id is unverified",
			results:     []resourcesresults.Result{result(resA, passed("C-0017"))},
			coverage:    complete(),
			item:        Item{"", "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonResourceIDMissing,
		},
		{
			// The resource may have been renamed, moved or deleted. Its absence
			// is never a fix.
			name:        "a resource missing from the rescan is not resolved",
			results:     []resourcesresults.Result{result(resB, passed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonResourceNotFound,
		},
		{
			name:        "an empty rescan resolves nothing",
			results:     nil,
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonResourceNotFound,
		},
		{
			name:        "two results for one resource id are ambiguous",
			results:     []resourcesresults.Result{result(resA, passed("C-0017")), result(resA, passed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonAmbiguousResource,
		},
		{
			name:        "a control the resource was not scanned for is not resolved",
			results:     []resourcesresults.Result{result(resA, passed("C-0001"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlNotFound,
		},
		{
			name:        "a control reported twice is ambiguous",
			results:     []resourcesresults.Result{result(resA, passed("C-0017"), passed("C-0017"))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonAmbiguousControl,
		},
		{
			name:        "a passed control with a sub-status is not a conclusive pass",
			results:     []resourcesresults.Result{result(resA, control("C-0017", apis.StatusPassed, apis.SubStatusException))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlSubStatus,
		},
		{
			name:        "a control marked not evaluated is unverified",
			results:     []resourcesresults.Result{result(resA, control("C-0017", apis.StatusPassed, apis.SubStatusNotEvaluated))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlNotEvaluated,
		},
		{
			name:        "a control with incomplete coverage is unverified",
			results:     []resourcesresults.Result{result(resA, control("C-0017", apis.StatusPassed, apis.SubStatusIncompleteCoverage))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlNotEvaluated,
		},
		{
			name:        "a skipped control is unverified",
			results:     []resourcesresults.Result{result(resA, control("C-0017", apis.StatusSkipped, apis.SubStatusUnknown))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlNotEvaluated,
		},
		{
			name:        "a control with a status that is neither passed nor failed is unverified",
			results:     []resourcesresults.Result{result(resA, control("C-0017", apis.ScanningStatus("mystery"), apis.SubStatusUnknown))},
			coverage:    complete(),
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlStatusUnknown,
		},
		{
			name:        "a control the scan lists as not evaluated is unverified whatever the report says",
			results:     []resourcesresults.Result{result(resA, passed("C-0017"))},
			coverage:    &cautils.ScanCoverage{NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "c-0017"}}},
			item:        Item{resA, "C-0017"},
			wantVerdict: VerdictUnverified, wantReason: ReasonControlNotEvaluated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(tt.results, tt.coverage, tt.degraded, tt.item)

			assert.Equal(t, tt.wantVerdict, got.Verdict)
			assert.Equal(t, tt.wantReason, got.Reason)
			if tt.wantVerdict == VerdictUnverified {
				assert.NotEmpty(t, got.Message, "an unverified verdict says why")
			} else {
				assert.Empty(t, got.Message)
			}
		})
	}
}

// TestClassifyDegradedScanNeverResolves: whatever makes a scan less than
// complete, a passed control on it is not a resolution.
func TestClassifyDegradedScanNeverResolves(t *testing.T) {
	results := []resourcesresults.Result{result(resA, passed("C-0017"))}
	item := Item{resA, "C-0017"}

	tests := []struct {
		name     string
		coverage *cautils.ScanCoverage
		degraded bool
	}{
		{"no coverage information", nil, false},
		{"the scan reports itself degraded", complete(), true},
		{"the coverage says degraded", &cautils.ScanCoverage{Degraded: true}, false},
		{"a manifest was skipped", &cautils.ScanCoverage{SkippedManifests: []cautils.SkippedManifest{{Path: "a.yaml", Reason: "parse error"}}}, false},
		{"a policy degraded", &cautils.ScanCoverage{PolicyDegradations: []cautils.PolicyDegradation{{Component: "controls inputs", Reason: "not loaded"}}}, false},
		{"a resource pull failed", &cautils.ScanCoverage{FailedGVRPulls: []cautils.FailedGVRPull{{GVR: "pods"}}}, false},
		{"a resource pull was partial", &cautils.ScanCoverage{PartialGVRPulls: []cautils.PartialGVRPull{{GVR: "pods"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Classify(&reporthandlingv2.PostureReport{Results: results}, tt.coverage, tt.degraded, []Item{item})

			assert.Equal(t, VerdictUnverified, resp.Results[0].Verdict)
			assert.Equal(t, ReasonCoverageInsufficient, resp.Results[0].Reason)
			assert.True(t, resp.Degraded)
			assert.Zero(t, resp.Summary.Resolved)
		})
	}
}

func TestClassifyKeepsInputOrderAndCounts(t *testing.T) {
	results := []resourcesresults.Result{
		result(resA, passed("C-0017")),
		result(resB, failed("C-0017")),
	}
	items := []Item{{resB, "C-0017"}, {resA, "C-0017"}, {"path=999/api=v1//Pod/gone", "C-0017"}, {resA, "C-0017"}}

	resp := Classify(&reporthandlingv2.PostureReport{Results: results}, complete(), false, items)

	require.Len(t, resp.Results, 4)
	for i, got := range resp.Results {
		assert.Equal(t, i, got.Index)
		assert.Equal(t, items[i].ResourceID, got.ResourceID)
	}
	assert.Equal(t, []string{VerdictStillFailing, VerdictResolved, VerdictUnverified, VerdictResolved},
		[]string{resp.Results[0].Verdict, resp.Results[1].Verdict, resp.Results[2].Verdict, resp.Results[3].Verdict})
	assert.Equal(t, Summary{Resolved: 2, StillFailing: 1, Unverified: 1}, resp.Summary)
	assert.False(t, resp.Degraded)
}

func TestClassifyNoItems(t *testing.T) {
	resp := Classify(&reporthandlingv2.PostureReport{}, complete(), false, nil)

	assert.Empty(t, resp.Results)
	assert.Equal(t, Summary{}, resp.Summary)
}

func TestClassifyReportJSON(t *testing.T) {
	envelope := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{
		PostureReport: &reporthandlingv2.PostureReport{Results: []resourcesresults.Result{result(resA, passed("C-0017"))}},
		ScanCoverage:  complete(),
	}
	raw, err := json.Marshal(&envelope)
	require.NoError(t, err)

	t.Run("a report with its coverage", func(t *testing.T) {
		resp, err := ClassifyReportJSON(raw, false, []Item{{resA, "C-0017"}})

		require.NoError(t, err)
		assert.Equal(t, VerdictResolved, resp.Results[0].Verdict)
	})
	t.Run("the scan's own degraded signal wins over complete coverage", func(t *testing.T) {
		resp, err := ClassifyReportJSON(raw, true, []Item{{resA, "C-0017"}})

		require.NoError(t, err)
		assert.Equal(t, VerdictUnverified, resp.Results[0].Verdict)
		assert.Equal(t, ReasonCoverageInsufficient, resp.Results[0].Reason)
	})
	t.Run("a report with no scanCoverage cannot confirm a pass", func(t *testing.T) {
		bare, err := json.Marshal(&reporthandlingv2.PostureReport{Results: envelope.Results})
		require.NoError(t, err)

		resp, err := ClassifyReportJSON(bare, false, []Item{{resA, "C-0017"}})

		require.NoError(t, err)
		assert.Equal(t, ReasonCoverageInsufficient, resp.Results[0].Reason)
	})
	t.Run("a report that cannot be parsed is an error, not a verdict", func(t *testing.T) {
		for _, bad := range []string{``, `not json`, `{"results": "x"}`, `[]`} {
			resp, err := ClassifyReportJSON([]byte(bad), false, []Item{{resA, "C-0017"}})

			require.Error(t, err, bad)
			assert.Contains(t, err.Error(), "failed to parse the fresh posture report")
			assert.Empty(t, resp.Results)
		}
	})
}

// TestResponseJSONShape pins the wire form the MCP tool returns: the field
// names, and that the message appears only for an unverified verdict.
func TestResponseJSONShape(t *testing.T) {
	resp := Classify(&reporthandlingv2.PostureReport{Results: []resourcesresults.Result{result(resA, failed("C-0017"))}},
		complete(), false, []Item{{resA, "C-0017"}, {resB, "C-0017"}})

	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.ElementsMatch(t, []string{"results", "summary", "degraded"}, keys(decoded))
	results := decoded["results"].([]any)
	first, second := results[0].(map[string]any), results[1].(map[string]any)
	assert.ElementsMatch(t, []string{"index", "resource_id", "control_id", "verdict", "reason"}, keys(first))
	assert.ElementsMatch(t, []string{"index", "resource_id", "control_id", "verdict", "reason", "message"}, keys(second))
	assert.ElementsMatch(t, []string{"resolved", "still_failing", "unverified"}, keys(decoded["summary"].(map[string]any)))
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestControlIDs(t *testing.T) {
	got := ControlIDs([]Item{{resA, "c-0017"}, {resB, "C-0017"}, {resA, " C-0001 "}, {resA, "C-0017"}})

	assert.Equal(t, []string{"C-0001", "C-0017"}, got, "distinct, normalized and sorted")
	assert.Empty(t, ControlIDs(nil))
}

func TestNormalizeControlID(t *testing.T) {
	assert.Equal(t, "C-0017", NormalizeControlID("  c-0017\t"))
	assert.Equal(t, "", NormalizeControlID("   "))
}

func TestExplanation(t *testing.T) {
	for _, reason := range []string{
		ReasonControlPassed, ReasonControlFailed, ReasonResourceIDMissing, ReasonResourceNotFound, ReasonAmbiguousResource,
		ReasonControlNotFound, ReasonAmbiguousControl, ReasonControlNotEvaluated, ReasonControlSubStatus,
		ReasonControlStatusUnknown, ReasonCoverageInsufficient,
	} {
		assert.NotEmpty(t, Explanation(reason), reason, "every reason code explains itself")
	}
	assert.Empty(t, Explanation("not-a-reason"))
}

// TestReportJSONAlwaysCarriesTheCoverage: a scan that completed cleanly has
// coverage with nothing in it, and it must still be in the report, or the
// verifier cannot tell it from a scan that says nothing about itself and would
// never confirm a pass.
func TestReportJSONAlwaysCarriesTheCoverage(t *testing.T) {
	report := &reporthandlingv2.PostureReport{Results: []resourcesresults.Result{result(resA, passed("C-0017"))}}

	t.Run("a clean scan's empty coverage is present", func(t *testing.T) {
		raw, err := ReportJSON(report, &cautils.ScanCoverage{})
		require.NoError(t, err)

		var decoded map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &decoded))
		assert.Contains(t, decoded, "scanCoverage")
		assert.Contains(t, decoded, "results")
	})
	t.Run("and a pass on it is confirmed", func(t *testing.T) {
		raw, err := ReportJSON(report, &cautils.ScanCoverage{EvaluatedControls: 1, TotalControls: 1})
		require.NoError(t, err)

		resp, err := ClassifyReportJSON(raw, false, []Item{{resA, "C-0017"}})

		require.NoError(t, err)
		assert.Equal(t, VerdictResolved, resp.Results[0].Verdict)
		assert.False(t, resp.Degraded)
	})
	t.Run("no coverage is left out, and then no pass is confirmed", func(t *testing.T) {
		raw, err := ReportJSON(report, nil)
		require.NoError(t, err)

		var decoded map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &decoded))
		assert.NotContains(t, decoded, "scanCoverage")
		resp, err := ClassifyReportJSON(raw, false, []Item{{resA, "C-0017"}})
		require.NoError(t, err)
		assert.Equal(t, ReasonCoverageInsufficient, resp.Results[0].Reason)
	})
}
