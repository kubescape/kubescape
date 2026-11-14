package watch

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// observe hands a scan to a baseline as a scan that succeeded.
func observe(t *testing.T, baseline *Baseline, doc scanDoc) *Observation {
	t.Helper()
	observation, err := baseline.Observe(doc.encode(t), nil, diff.Options{})
	require.NoError(t, err)
	return observation
}

// withPolicyFallback records that a policy input came from a fallback, as a scan
// that could not download the released policies does.
func withPolicyFallback(doc scanDoc) scanDoc {
	coverage := doc["scanCoverage"].(map[string]any)
	coverage["policyDegradations"] = []any{map[string]any{"component": "controlInputs", "reason": "failed to fetch from GitHub, loaded from local cache"}}
	coverage["degraded"] = true
	return doc
}

func TestBaselineStartsWithTheFirstCompleteScan(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	require.False(t, baseline.Has())

	observation := observe(t, baseline, completeScan(t, loadScan(t, "two_files")))

	assert.True(t, observation.Initial)
	assert.True(t, observation.Advanced)
	assert.Nil(t, observation.Result, "there was nothing to compare with")
	assert.Empty(t, observation.Gaps)
	assert.True(t, baseline.Has())
}

func TestBaselineWaitsForAFirstScanThatIsComplete(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()

	// The first scan could not load a manifest: a real scan's own report says so.
	first := observe(t, baseline, loadScan(t, "two_files_one_invalid"))
	assert.False(t, first.Advanced)
	assert.False(t, first.Initial)
	assert.Nil(t, first.Result)
	require.NotEmpty(t, first.Gaps)
	assert.Contains(t, strings.Join(first.Gaps, "; "), "skipped")
	assert.False(t, baseline.Has(), "an incomplete scan is not a baseline: what it left out would be new in the next one")

	second := observe(t, baseline, completeScan(t, loadScan(t, "two_files")))
	assert.True(t, second.Initial)
	assert.True(t, baseline.Has())
}

func TestBaselineAdvancesAfterACompleteScan(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	observe(t, baseline, completeScan(t, loadScan(t, "base")))

	// The frontend is edited: one finding is fixed.
	second := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
	require.NotNil(t, second.Result)
	assert.NotEmpty(t, second.Result.Resolved)
	assert.True(t, second.Advanced)
	assert.False(t, second.Initial)

	// The next scan is compared with the second, not with the first: nothing has
	// changed since the edit, so nothing is resolved again.
	third := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
	require.NotNil(t, third.Result)
	assert.Empty(t, third.Result.Resolved, "it was compared with the scan before it")
	assert.Empty(t, third.Result.New)
	assert.NotEmpty(t, third.Result.Existing)
}

func TestBaselineIsKeptWhenAScanFails(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	observe(t, baseline, completeScan(t, loadScan(t, "base")))
	boom := errors.New("could not download the policies")

	observation, err := baseline.Observe(completeScan(t, loadScan(t, "edited_and_prepended")).encode(t), boom, diff.Options{})

	require.Error(t, err)
	assert.ErrorIs(t, err, boom, "the cause is not lost")
	assert.Contains(t, err.Error(), "baseline is kept")
	assert.Nil(t, observation)
	// The failed scan did not replace it: the next scan is compared with the
	// original, and finds the edit as resolved.
	next := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
	require.NotNil(t, next.Result)
	assert.NotEmpty(t, next.Result.Resolved)
}

func TestBaselineIsNotCreatedByAFailedFirstScan(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()

	_, err := baseline.Observe(nil, errors.New("no resources found to scan"), diff.Options{})

	require.Error(t, err)
	assert.False(t, baseline.Has())
}

func TestBaselineIsKeptWhenAScanIsIncomplete(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	observe(t, baseline, completeScan(t, loadScan(t, "two_files")))

	// b.yaml could not be loaded: compared, and not a baseline.
	incomplete := observe(t, baseline, loadScan(t, "two_files_one_invalid"))
	require.NotNil(t, incomplete.Result, "what the scan did read is still compared")
	assert.False(t, incomplete.Advanced)
	assert.NotEmpty(t, incomplete.Gaps)
	assert.Empty(t, incomplete.Result.Removed, "an unread manifest is not a removed one")
	assert.Empty(t, incomplete.Result.Resolved)
	assert.NotZero(t, findingsOn(incomplete.Result.Incomparable, backendInB))

	// The complete scan that follows is compared with the baseline from before,
	// which still has the backend: nothing is new, as it would be against the
	// incomplete scan that lacked it.
	complete := observe(t, baseline, completeScan(t, loadScan(t, "two_files")))
	require.NotNil(t, complete.Result)
	assert.Empty(t, complete.Result.New, "it was not compared with the scan that was missing the backend")
	assert.Empty(t, complete.Result.Incomparable)
	assert.True(t, complete.Advanced)
}

func TestBaselineAdvancesWhenOnlyPolicyInputsCameFromAFallback(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	observe(t, baseline, completeScan(t, loadScan(t, "two_files")))

	// Offline, every scan has its policies from the local cache. The coverage is
	// otherwise complete, so the scan is a baseline; if it were not, the baseline
	// would never advance for the whole of the session.
	offline := observe(t, baseline, withPolicyFallback(completeScan(t, loadScan(t, "two_files"))))
	assert.True(t, offline.Advanced)
	assert.Empty(t, offline.Gaps)
	require.NotEmpty(t, offline.Notes)
	assert.Contains(t, offline.Notes[0], "controlInputs")

	again := observe(t, baseline, withPolicyFallback(completeScan(t, loadScan(t, "two_files"))))
	assert.True(t, again.Advanced, "and it keeps advancing")
	require.NotNil(t, again.Result)
	assert.Empty(t, again.Result.New)
	assert.Empty(t, again.Result.Resolved)
}

func TestBaselineAdvancingOnAFallbackDoesNotMakeAbsentFindingsRemoved(t *testing.T) {
	t.Parallel()
	// Advancing does not make the comparison less careful. With the policies from
	// a fallback the verdicts may differ, so a finding that is simply absent from
	// the scan, because its resource is, is not called removed: that the file was
	// deleted cannot be told from the scan having evaluated less.
	baseline := NewBaseline()
	two := completeScan(t, loadScan(t, "two_files"))
	observe(t, baseline, two)

	fallback := observe(t, baseline, withPolicyFallback(completeScan(t, two.without(t, "b.yaml"))))

	require.NotNil(t, fallback.Result)
	assert.Empty(t, fallback.Result.Removed)
	assert.Empty(t, fallback.Result.Resolved)
	assert.NotZero(t, findingsOn(fallback.Result.Incomparable, backendInB), "its findings are incomparable, with the reason")
	assert.True(t, fallback.Advanced, "and the scan is still the baseline")
}

func TestBaselineIsKeptWhenTheReportCannotBeCompared(t *testing.T) {
	t.Parallel()

	t.Run("a report without the resources a comparison needs", func(t *testing.T) {
		t.Parallel()
		baseline := NewBaseline()
		observe(t, baseline, completeScan(t, loadScan(t, "base")))
		omitted := completeScan(t, loadScan(t, "edited_and_prepended"))
		omitted["resources"] = []any{} // as with --omit-raw-resources

		observation, err := baseline.Observe(omitted.encode(t), nil, diff.Options{})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoResourceIdentity)
		assert.Contains(t, err.Error(), "baseline is kept")
		assert.Nil(t, observation)
		next := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
		require.NotNil(t, next.Result)
		assert.NotEmpty(t, next.Result.Resolved, "still compared with the original baseline")
	})

	t.Run("a first report that cannot be a baseline", func(t *testing.T) {
		t.Parallel()
		baseline := NewBaseline()
		omitted := completeScan(t, loadScan(t, "base"))
		omitted["resources"] = []any{}

		_, err := baseline.Observe(omitted.encode(t), nil, diff.Options{})

		require.Error(t, err)
		assert.False(t, baseline.Has(), "nothing is half made")
	})

	t.Run("a report that is not a report", func(t *testing.T) {
		t.Parallel()
		baseline := NewBaseline()
		observe(t, baseline, completeScan(t, loadScan(t, "base")))

		for _, raw := range []string{``, `not json`, `[]`, `null`, `{"results": 5}`} {
			_, err := baseline.Observe([]byte(raw), nil, diff.Options{})
			assert.Error(t, err, raw)
		}
		assert.True(t, baseline.Has())
		next := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
		assert.NotEmpty(t, next.Result.Resolved)
	})

	t.Run("an invalid granularity", func(t *testing.T) {
		t.Parallel()
		baseline := NewBaseline()
		observe(t, baseline, completeScan(t, loadScan(t, "base")))

		_, err := baseline.Observe(completeScan(t, loadScan(t, "edited_and_prepended")).encode(t), nil, diff.Options{Granularity: "nonsense"})

		require.Error(t, err)
		next := observe(t, baseline, completeScan(t, loadScan(t, "edited_and_prepended")))
		assert.NotEmpty(t, next.Result.Resolved, "the failed comparison did not move the baseline")
	})
}

func TestBaselineSeesRenamesAndRemovalsAcrossScans(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	two := completeScan(t, loadScan(t, "two_files"))
	observe(t, baseline, two)

	renamed := observe(t, baseline, completeScan(t, two.renamed(t, "a.yaml", "renamed.yaml")))
	require.NotNil(t, renamed.Result)
	assert.Equal(t, []Rename{{From: frontendInA, To: frontendMoved}}, renamed.Result.Renames)
	assert.Empty(t, renamed.Result.New)
	assert.Empty(t, renamed.Result.Removed)
	assert.True(t, renamed.Advanced)

	// The next scan is compared with the renamed one: the file's new name is its
	// identity now, and deleting it removes the resource.
	removed := observe(t, baseline, completeScan(t, two.renamed(t, "a.yaml", "renamed.yaml").without(t, "renamed.yaml")))
	require.NotNil(t, removed.Result)
	assert.NotZero(t, findingsOn(removed.Result.Removed, frontendMoved))
	assert.Empty(t, removed.Result.Renames)
}

func TestCoverageGaps(t *testing.T) {
	t.Parallel()
	complete := func() map[string]any {
		return map[string]any{"coverageScore": 100, "evaluatedControls": 60, "totalControls": 60, "degraded": false}
	}
	with := func(edit func(coverage map[string]any)) map[string]any {
		coverage := complete()
		edit(coverage)
		return coverage
	}
	tests := []struct {
		name      string
		coverage  any // the scanCoverage of the report
		wantGaps  string
		wantNotes string
	}{
		{name: "complete", coverage: complete()},
		{name: "no coverage in the report", coverage: nil, wantGaps: "no scanCoverage"},
		{name: "nothing in scope", coverage: with(func(c map[string]any) { c["totalControls"] = 0; c["evaluatedControls"] = 0; c["degraded"] = true }), wantGaps: "nothing was evaluated"},
		{name: "resource types that could not be read", coverage: with(func(c map[string]any) {
			c["failedGVRPulls"] = []any{map[string]any{"gvr": "apps/v1/deployments", "controls": []any{"C-0013"}}}
			c["degraded"] = true
		}), wantGaps: "could not be read"},
		{name: "resource types read in part", coverage: with(func(c map[string]any) {
			c["partialGVRPulls"] = []any{map[string]any{"gvr": "/v1/pods", "selector": "app=x", "error": "timeout"}}
			c["degraded"] = true
		}), wantGaps: "read in part"},
		{name: "a manifest skipped", coverage: with(func(c map[string]any) {
			c["skippedManifests"] = []any{map[string]any{"path": "b.yaml", "reason": "invalid YAML"}}
			c["degraded"] = true
		}), wantGaps: "1 manifest(s) were skipped"},
		{name: "controls not evaluated", coverage: with(func(c map[string]any) {
			c["notEvaluatedControls"] = []any{map[string]any{"controlID": "C-0099"}, map[string]any{"controlID": "C-0001"}}
			c["degraded"] = true
		}), wantGaps: "2 control(s) were not evaluated: C-0001, C-0099"},
		{name: "degraded with no cause recorded", coverage: with(func(c map[string]any) { c["degraded"] = true }), wantGaps: "degraded with no recorded cause"},
		{name: "policy input from a fallback only", coverage: with(func(c map[string]any) {
			c["policyDegradations"] = []any{map[string]any{"component": "exceptions", "reason": "cache"}, map[string]any{"component": "controlInputs", "reason": "cache"}}
			c["degraded"] = true
		}), wantNotes: "2 policy input(s) came from a fallback: controlInputs, exceptions"},
		{name: "a fallback and a skipped manifest", coverage: with(func(c map[string]any) {
			c["policyDegradations"] = []any{map[string]any{"component": "exceptions", "reason": "cache"}}
			c["skippedManifests"] = []any{map[string]any{"path": "b.yaml"}}
			c["degraded"] = true
		}), wantGaps: "skipped", wantNotes: "fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := loadScan(t, "two_files")
			if tt.coverage != nil {
				doc["scanCoverage"] = tt.coverage
			}
			gaps, notes, err := coverageOf(doc.encode(t))
			require.NoError(t, err)
			if tt.wantGaps == "" {
				assert.Empty(t, gaps)
			} else {
				assert.Contains(t, strings.Join(gaps, "; "), tt.wantGaps)
			}
			if tt.wantNotes == "" {
				assert.Empty(t, notes)
			} else {
				assert.Contains(t, strings.Join(notes, "; "), tt.wantNotes)
			}
		})
	}
}

func TestBaselineIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()
	baseline := NewBaseline()
	scan := completeScan(t, loadScan(t, "two_files")).encode(t)
	incomplete := loadScan(t, "two_files_one_invalid").encode(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				raw := scan
				if (i+j)%3 == 0 {
					raw = incomplete
				}
				_, err := baseline.Observe(raw, nil, diff.Options{})
				assert.NoError(t, err)
				_ = baseline.Has()
			}
		}()
	}
	wg.Wait()
	assert.True(t, baseline.Has(), fmt.Sprint("the baseline after ", 160, " scans"))
}
