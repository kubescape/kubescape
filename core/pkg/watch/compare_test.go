package watch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compare(t *testing.T, base, head []byte) *Comparison {
	t.Helper()
	comparison, err := Compare(base, head, diff.Options{})
	require.NoError(t, err)
	return comparison
}

func resourceIDs(changes []diff.ControlChange) []string {
	seen := map[string]struct{}{}
	var ids []string
	for _, change := range changes {
		if _, ok := seen[change.ResourceID]; !ok {
			seen[change.ResourceID] = struct{}{}
			ids = append(ids, change.ResourceID)
		}
	}
	return ids
}

const (
	webID = "multi.yaml::apps/v1::default::Deployment::web"
	apiID = "multi.yaml::apps/v1::default::Deployment::api"
)

func TestCompareInsertingADocumentIsNotAChange(t *testing.T) {
	base := buildReport(t, []fixtureResource{
		deployment("path=100/web", "multi.yaml", "web", "C-0001"),
		deployment("path=101/api", "multi.yaml", "api", "C-0002"),
	})
	// A ConfigMap is prepended: web and api shift down by one position.
	head := buildReport(t, []fixtureResource{
		{ID: "path=100/cm", File: "multi.yaml", APIVer: "v1", Kind: "ConfigMap", Namespace: "default", Name: "cm"},
		deployment("path=101/web", "multi.yaml", "web", "C-0001"),
		deployment("path=102/api", "multi.yaml", "api", "C-0002"),
	})

	// The positional IDs make the plain diff wrong, which is the reason this package exists.
	plain, err := diff.ComputeFromJSON(base, head, diff.Options{})
	require.NoError(t, err)
	require.NotEmpty(t, plain.New, "fixture must reproduce the false findings")
	require.NotEmpty(t, plain.Resolved)

	got := compare(t, base, head)
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Empty(t, got.Removed)
	assert.Empty(t, got.ChangeSet.Incomparable)
	assert.ElementsMatch(t, []string{webID, apiID}, resourceIDs(got.ChangeSet.Unchanged))
}

func TestCompareDeletingTheFirstDocumentOnlyRemovesThatResource(t *testing.T) {
	base := buildReport(t, []fixtureResource{
		deployment("path=100/web", "multi.yaml", "web", "C-0001"),
		deployment("path=101/api", "multi.yaml", "api", "C-0002"),
	})
	head := buildReport(t, []fixtureResource{
		deployment("path=100/api", "multi.yaml", "api", "C-0002"), // api moved up
	})

	got := compare(t, base, head)
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.ChangeSet.Resolved, "a deleted resource was not fixed")
	assert.Equal(t, []string{webID}, resourceIDs(got.Removed))
	assert.Equal(t, []string{apiID}, resourceIDs(got.ChangeSet.Unchanged))
}

func TestCompareFixingAFindingIsResolvedNotRemoved(t *testing.T) {
	base := buildReport(t, []fixtureResource{deployment("path=100/web", "multi.yaml", "web", "C-0001", "C-0002")})
	head := buildReport(t, []fixtureResource{
		{ID: "path=100/cm", File: "multi.yaml", APIVer: "v1", Kind: "ConfigMap", Namespace: "default", Name: "cm"},
		deployment("path=101/web", "multi.yaml", "web", "C-0002"),
	})

	got := compare(t, base, head)
	require.Len(t, got.ChangeSet.Resolved, 1)
	assert.Equal(t, "C-0001", got.ChangeSet.Resolved[0].ControlID)
	assert.Equal(t, webID, got.ChangeSet.Resolved[0].ResourceID)
	assert.Empty(t, got.Removed)
	assert.Empty(t, got.ChangeSet.New)
	assert.Len(t, got.ChangeSet.Unchanged, 1)
}

func TestCompareNewFindingAndNewResource(t *testing.T) {
	base := buildReport(t, []fixtureResource{deployment("path=100/web", "multi.yaml", "web", "C-0001")})
	head := buildReport(t, []fixtureResource{
		deployment("path=100/web", "multi.yaml", "web", "C-0001", "C-0002"),
		deployment("path=101/api", "multi.yaml", "api", "C-0001"),
	})

	got := compare(t, base, head)
	assert.ElementsMatch(t, []string{webID, apiID}, resourceIDs(got.ChangeSet.New))
	assert.Len(t, got.ChangeSet.New, 2)
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Len(t, got.ChangeSet.Unchanged, 1)
}

func TestCompareFindingsInOtherFilesAreUnaffected(t *testing.T) {
	base := buildReport(t, []fixtureResource{
		deployment("path=1/web", "a.yaml", "web", "C-0001"),
		deployment("path=2/web", "b.yaml", "web", "C-0001"),
	})
	head := buildReport(t, []fixtureResource{
		deployment("path=2/web", "b.yaml", "web", "C-0001"),
	})

	got := compare(t, base, head)
	assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.Removed))
	assert.Equal(t, []string{"b.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.ChangeSet.Unchanged))
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.ChangeSet.Resolved)
}

func TestCompareSameNameInDifferentFilesOrNamespacesStaysDistinct(t *testing.T) {
	prod := deployment("path=3/web", "a.yaml", "web", "C-0001")
	prod.Namespace = "prod"
	base := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001"), prod})
	headProd := deployment("path=2/web", "a.yaml", "web", "C-0001")
	headProd.Namespace = "prod"
	// Only the default namespace's copy is fixed.
	head := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web"), headProd})

	got := compare(t, base, head)
	assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.ChangeSet.Resolved))
	assert.Equal(t, []string{"a.yaml::apps/v1::prod::Deployment::web"}, resourceIDs(got.ChangeSet.Unchanged))
}

func TestCompareDuplicateIdentityIsIncomparable(t *testing.T) {
	duplicated := []fixtureResource{
		deployment("path=1/web", "multi.yaml", "web", "C-0001"),
		deployment("path=2/web", "multi.yaml", "web"),
		deployment("path=3/api", "multi.yaml", "api", "C-0002"),
	}
	unique := []fixtureResource{
		deployment("path=1/web", "multi.yaml", "web", "C-0001"),
		deployment("path=3/api", "multi.yaml", "api", "C-0002"),
	}

	tests := []struct {
		name       string
		base, head []fixtureResource
	}{
		{"duplicate in both scans", duplicated, duplicated},
		{"duplicate only in the head scan", unique, duplicated},
		{"duplicate only in the base scan", duplicated, unique},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compare(t, buildReport(t, tt.base), buildReport(t, tt.head))
			cs := got.ChangeSet

			for _, bucket := range [][]diff.ControlChange{cs.New, cs.Resolved, cs.Unchanged, got.Removed} {
				assert.NotContains(t, resourceIDs(bucket), webID, "an ambiguous resource must not be classified")
			}
			assert.Equal(t, []string{apiID}, resourceIDs(cs.Unchanged), "the unambiguous neighbour is still compared")
			require.NotEmpty(t, cs.Warnings)
			assert.Contains(t, cs.Warnings[0], webID)
			if tt.name != "duplicate in both scans" {
				// The resource exists on one side with findings, so they are reported, not dropped.
				require.Contains(t, resourceIDs(cs.Incomparable), webID)
				assert.NotEmpty(t, cs.Incomparable[0].Reason)
			}
		})
	}
}

func TestCompareDegradedHeadCoverageNeverResolves(t *testing.T) {
	base := buildReport(t, []fixtureResource{
		deployment("path=1/web", "a.yaml", "web", "C-0001"),
		deployment("path=2/api", "b.yaml", "api", "C-0001"),
	})
	head := buildReport(t, []fixtureResource{
		deployment("path=2/api", "b.yaml", "api", "C-0001"),
	}, withCoverage(map[string]any{
		"degraded":         true,
		"skippedManifests": []any{map[string]any{"path": "a.yaml", "reason": "parse error"}},
	}))

	got := compare(t, base, head)
	assert.Empty(t, got.Removed, "a missing resource is not removed when coverage is degraded")
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.ChangeSet.Incomparable))
	assert.Equal(t, []string{"b.yaml::apps/v1::default::Deployment::api"}, resourceIDs(got.ChangeSet.Unchanged))
}

func TestCompareNotEvaluatedControlNeverResolves(t *testing.T) {
	base := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")})

	t.Run("control present but not evaluated", func(t *testing.T) {
		head := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web")}, withSubStatus("notEvaluated"))
		got := compare(t, base, head)
		assert.Empty(t, got.ChangeSet.Resolved)
		assert.Empty(t, got.Removed)
		assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.ChangeSet.Incomparable))
	})

	t.Run("resource gone and control listed as not evaluated", func(t *testing.T) {
		head := buildReport(t, nil, withCoverage(map[string]any{
			"degraded":             true,
			"notEvaluatedControls": []any{map[string]any{"controlID": "C-0001", "reason": "timeout"}},
		}))
		got := compare(t, base, head)
		assert.Empty(t, got.ChangeSet.Resolved)
		assert.Empty(t, got.Removed)
		assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.ChangeSet.Incomparable))
	})
}

func TestCompareEmptyHeadScan(t *testing.T) {
	base := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")})
	head := []byte(`{"results":[],"summaryDetails":{"controls":{"C-0001":{"scoreFactor":7}}}}`)

	got := compare(t, base, head)
	assert.Equal(t, []string{"a.yaml::apps/v1::default::Deployment::web"}, resourceIDs(got.Removed))
	assert.Empty(t, got.ChangeSet.New)
}

func TestCompareRejectsReportsItCannotIdentify(t *testing.T) {
	good := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")})
	noResources := []byte(`{"results":[{"resourceID":"path=1/web","controls":[]}],"summaryDetails":{"controls":{}}}`)

	_, err := Compare(noResources, good, diff.Options{})
	require.ErrorIs(t, err, ErrNoResourceIdentity)
	assert.Contains(t, err.Error(), "base report")
	_, err = Compare(good, noResources, diff.Options{})
	require.ErrorIs(t, err, ErrNoResourceIdentity)
	assert.Contains(t, err.Error(), "head report")

	_, err = Compare([]byte(`{`), good, diff.Options{})
	require.Error(t, err)
}

func TestCompareHonoursGranularity(t *testing.T) {
	base := buildReport(t, []fixtureResource{deployment("path=1/web", "a.yaml", "web", "C-0001")})
	_, err := Compare(base, base, diff.Options{Granularity: "bogus"})
	require.Error(t, err)

	got, err := Compare(base, base, diff.Options{Granularity: diff.GranularityControl})
	require.NoError(t, err)
	assert.Len(t, got.ChangeSet.Unchanged, 1)
}

// The fixtures below are real "kubescape scan framework nsa --format json"
// reports of a directory that was edited in place between scans, with machine
// specific paths replaced.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	require.NoError(t, err)
	return data
}

func countControls(changes []diff.ControlChange, resource string) int {
	n := 0
	for _, change := range changes {
		if change.ResourceID == resource {
			n++
		}
	}
	return n
}

const (
	realFrontend = "multi.yaml::apps/v1::default::Deployment::frontend"
	realBackend  = "multi.yaml::apps/v1::default::Deployment::backend"
)

func TestCompareRealReportsPrependedDocument(t *testing.T) {
	base, head := fixture(t, "base"), fixture(t, "prepended")

	plain, err := diff.ComputeFromJSON(base, head, diff.Options{})
	require.NoError(t, err)
	require.Len(t, plain.New, 21, "raw positional IDs report every finding as new")
	require.Len(t, plain.Resolved, 21, "and as resolved")

	got := compare(t, base, head)
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Empty(t, got.ChangeSet.Incomparable)
	assert.Empty(t, got.Removed)
	assert.Len(t, got.ChangeSet.Unchanged, 21)
}

func TestCompareRealReportsEditAndPrependTogether(t *testing.T) {
	got := compare(t, fixture(t, "base"), fixture(t, "edited_and_prepended"))
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.Removed)
	require.Len(t, got.ChangeSet.Resolved, 1)
	assert.Equal(t, "C-0057", got.ChangeSet.Resolved[0].ControlID)
	assert.Equal(t, realFrontend, got.ChangeSet.Resolved[0].ResourceID)
	assert.Len(t, got.ChangeSet.Unchanged, 20)
}

func TestCompareRealReportsFirstDocumentRemoved(t *testing.T) {
	got := compare(t, fixture(t, "base"), fixture(t, "first_removed"))
	assert.Empty(t, got.ChangeSet.New, "backend moved up but did not change")
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Equal(t, 11, countControls(got.Removed, realFrontend))
	assert.Equal(t, 10, countControls(got.ChangeSet.Unchanged, realBackend))
}

func TestCompareRealReportsInvalidFileMakesRemovalIncomparable(t *testing.T) {
	// b.yaml no longer parses, so its resource is missing from the head scan
	// and the report says manifests were skipped.
	got := compare(t, fixture(t, "two_files"), fixture(t, "two_files_one_invalid"))
	assert.Empty(t, got.Removed)
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Empty(t, got.ChangeSet.New)
	assert.Equal(t, 10, countControls(got.ChangeSet.Incomparable, "b.yaml::apps/v1::default::Deployment::backend"))
	assert.Equal(t, 11, countControls(got.ChangeSet.Unchanged, "a.yaml::apps/v1::default::Deployment::frontend"))
}

func TestCompareRealReportsDuplicateIdentity(t *testing.T) {
	report := fixture(t, "duplicate_identity")

	// The plain engine would hard-fail on the collision a naive rewrite creates;
	// here the duplicates are set aside and the rest still compares.
	got := compare(t, report, report)
	dup := "dup.yaml::apps/v1::default::Deployment::frontend"
	require.NotEmpty(t, got.ChangeSet.Warnings)
	assert.Contains(t, got.ChangeSet.Warnings[0], dup)
	assert.Zero(t, countControls(got.ChangeSet.Unchanged, dup))
	assert.Empty(t, got.ChangeSet.New)
	assert.Empty(t, got.ChangeSet.Resolved)
	assert.Equal(t, 10, countControls(got.ChangeSet.Unchanged, "dup.yaml::apps/v1::default::Deployment::backend"))
}
