package policyhandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/stretchr/testify/require"
)

func controlPolicyGetter(t *testing.T, framework string) *getter.LoadPolicy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fw.json")
	require.NoError(t, os.WriteFile(path, []byte(framework), 0o600))
	return getter.NewLoadPolicy([]string{path})
}

func controlIdentifiers(ids ...string) []cautils.PolicyIdentifier {
	out := make([]cautils.PolicyIdentifier, len(ids))
	for i, id := range ids {
		out[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	return out
}

func downloadedControlIDs(t *testing.T, lp *getter.LoadPolicy, ids ...string) ([]string, error) {
	t.Helper()
	policies, err := NewPolicyHandler("control-identifier-test").downloadScanPolicies(
		context.Background(), controlIdentifiers(ids...), &cautils.Getters{PolicyGetter: lp})
	if err != nil {
		return nil, err
	}
	var got []string
	for _, fw := range policies {
		for _, c := range fw.Controls {
			got = append(got, c.ControlID)
		}
	}
	return got, nil
}

const sectionFramework = `{"name":"cis","controls":[
 {"controlID":"C-0286","id":"CIS-3.1.1","name":"a"},
 {"controlID":"C-0287","id":"CIS-3.1.2","name":"b"},
 {"controlID":"C-0012","name":"c"}]}`

func TestDownloadScanPoliciesResolvesControlSectionIdentifier(t *testing.T) {
	lp := controlPolicyGetter(t, sectionFramework)

	got, err := downloadedControlIDs(t, lp, "cis-3.1.1", "C-0012")
	require.NoError(t, err)
	require.Equal(t, []string{"C-0286", "C-0012"}, got)
}

// Naming one control by both identifiers must not scan it twice.
func TestDownloadScanPoliciesDeduplicatesControlAliases(t *testing.T) {
	lp := controlPolicyGetter(t, sectionFramework)

	for _, ids := range [][]string{
		{"C-0286", "CIS-3.1.1"},
		{"CIS-3.1.1", "c-0286"},
		{"C-0012", "C-0012"},
	} {
		got, err := downloadedControlIDs(t, lp, ids...)
		require.NoError(t, err, "%v", ids)
		require.Len(t, got, 1, "%v", ids)
	}
}

func TestDownloadScanPoliciesControlIdentifierErrors(t *testing.T) {
	t.Run("unknown is reported with the identifier", func(t *testing.T) {
		_, err := downloadedControlIDs(t, controlPolicyGetter(t, sectionFramework), "CIS-9.9.9")
		require.ErrorIs(t, err, getter.ErrControlNotMatching)
		require.ErrorContains(t, err, "CIS-9.9.9")
	})
	t.Run("ambiguous section number is reported, not reported as unknown", func(t *testing.T) {
		lp := controlPolicyGetter(t, `{"name":"x","controls":[
 {"controlID":"C-0001","id":"X-1"},{"controlID":"C-0002","id":"X-1"}]}`)
		_, err := downloadedControlIDs(t, lp, "x-1")
		require.ErrorIs(t, err, getter.ErrControlAmbiguous)
		require.NotContains(t, err.Error(), "not found")
	})
}

// persistentControlGetter reads from a local framework like LoadPolicy but, as
// the released-policy getter does, publishes what it resolves to the cache.
type persistentControlGetter struct {
	*getter.LoadPolicy
}

func (persistentControlGetter) ShouldPersistPolicyArtifacts() bool { return true }

// Every requested identifier must be cached, even when another one already
// resolved to the same control, because an offline lookup reads the cache file
// named after the identifier it was given.
func TestDownloadScanPoliciesCachesEveryControlAlias(t *testing.T) {
	for _, ids := range [][]string{
		{"CIS-3.1.1", "C-0286"},
		{"C-0286", "CIS-3.1.1"},
	} {
		t.Run(ids[0]+","+ids[1], func(t *testing.T) {
			store := t.TempDir()
			prev := getter.DefaultLocalStore
			getter.DefaultLocalStore = store
			t.Cleanup(func() { getter.DefaultLocalStore = prev })

			g := persistentControlGetter{controlPolicyGetter(t, sectionFramework)}
			policies, err := NewPolicyHandler("control-cache-test").downloadScanPolicies(
				context.Background(), controlIdentifiers(ids...), &cautils.Getters{PolicyGetter: g})
			require.NoError(t, err)

			// The scanned controls stay deduplicated.
			require.Len(t, policies, 1)
			require.Len(t, policies[0].Controls, 1)
			require.Equal(t, "C-0286", policies[0].Controls[0].ControlID)

			// Both identifiers are cached.
			for _, id := range ids {
				path, err := getter.PolicyCachePath(id)
				require.NoError(t, err)
				require.FileExists(t, path, id)
			}

			// An offline --use-default scan of either identifier finds its
			// cache file and resolves it without the original source.
			for _, id := range ids {
				scanInfo := &cautils.ScanInfo{UseDefault: true}
				require.NoError(t, scanInfo.Init(context.Background(), controlIdentifiers(id)))
				control, err := getter.NewLoadPolicy(scanInfo.UseFrom).GetControl(id)
				require.NoError(t, err, id)
				require.Equal(t, "C-0286", control.ControlID, id)
			}
		})
	}
}
