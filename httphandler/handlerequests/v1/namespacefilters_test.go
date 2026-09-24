package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/httphandler/config"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
)

func TestLiveNamespaceDefaultsForScanAndMetrics(t *testing.T) {
	withTempOutputDirs(t)
	t.Setenv("KS_INCLUDE_NAMESPACES", "old-include")
	t.Setenv("KS_EXCLUDE_NAMESPACES", "old-exclude")
	path := filepath.Join(t.TempDir(), "namespaceFilters.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":["prod"],"excludeNamespaces":[]}`), 0o600))
	require.NoError(t, config.ConfigureNamespaceFilters(path))
	t.Cleanup(func() { require.NoError(t, config.ConfigureNamespaceFilters("")) })
	previousScanner := scanImpl
	t.Cleanup(func() { scanImpl = previousScanner })
	captured := make(chan config.NamespaceFilters, 1)
	scanImpl = func(_ context.Context, info *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		captured <- config.NamespaceFilters{Include: info.IncludeNamespaces, Exclude: info.ExcludedNamespaces}
		return nil, os.WriteFile(info.Output, []byte("{}"), 0o600)
	}
	handler := NewHTTPHandler(false)
	t.Cleanup(func() { require.NoError(t, handler.Shutdown(context.Background(), time.Second)) })
	for _, tt := range []struct {
		name, document string
		want           config.NamespaceFilters
	}{
		{"initial", `{"includeNamespaces":["prod"],"excludeNamespaces":[]}`, config.NamespaceFilters{Include: "prod"}},
		{"expand include", `{"includeNamespaces":["prod","payments"],"excludeNamespaces":[]}`, config.NamespaceFilters{Include: "prod,payments"}},
		{"switch to exclude", `{"includeNamespaces":[],"excludeNamespaces":["payments"]}`, config.NamespaceFilters{Exclude: "payments"}},
		{"invalid update", `{"includeNamespaces":[],"excludeNamespaces":null}`, config.NamespaceFilters{Exclude: "payments"}},
		{"clear both", `{"includeNamespaces":[],"excludeNamespaces":[]}`, config.NamespaceFilters{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(path, []byte(tt.document), 0o600))
			for _, endpoint := range []string{"scan", "metrics"} {
				response := httptest.NewRecorder()
				if endpoint == "scan" {
					handler.Scan(response, httptest.NewRequest(http.MethodPost, "/v1/scan?wait=true", strings.NewReader(`{}`)))
				} else {
					handler.Metrics(response, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
				}
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				select {
				case got := <-captured:
					require.Equal(t, tt.want, got, endpoint)
				case <-time.After(5 * time.Second):
					t.Fatal("scan did not reach worker")
				}
			}
		})
	}
}

func TestNamespaceDefaultsCompatibilityAndSnapshots(t *testing.T) {
	t.Setenv("KS_INCLUDE_NAMESPACES", "legacy")
	t.Setenv("KS_EXCLUDE_NAMESPACES", "legacy-exclude")
	require.NoError(t, config.ConfigureNamespaceFilters(""))
	t.Cleanup(func() { require.NoError(t, config.ConfigureNamespaceFilters("")) })
	legacy, _ := ToScanInfo(&utilsmetav1.PostScanRequest{})
	require.Equal(t, "legacy", legacy.IncludeNamespaces)
	require.Equal(t, "legacy-exclude", legacy.ExcludedNamespaces)
	path := filepath.Join(t.TempDir(), "namespaceFilters.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":["prod"],"excludeNamespaces":["test"]}`), 0o600))
	require.NoError(t, config.ConfigureNamespaceFilters(path))
	before, _ := ToScanInfo(&utilsmetav1.PostScanRequest{})
	override, _ := ToScanInfo(&utilsmetav1.PostScanRequest{
		IncludeNamespaces: []string{"request-include"}, ExcludedNamespaces: []string{"request-exclude"},
	})
	require.Equal(t, "request-include", override.IncludeNamespaces)
	require.Equal(t, "request-exclude", override.ExcludedNamespaces)
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":[]}`), 0o600))
	after, _ := ToScanInfo(&utilsmetav1.PostScanRequest{})
	require.Empty(t, after.IncludeNamespaces)
	require.Empty(t, after.ExcludedNamespaces)
	// Already prepared/queued scans keep their original snapshot.
	require.Equal(t, "prod", before.IncludeNamespaces)
	require.Equal(t, "test", before.ExcludedNamespaces)
}
