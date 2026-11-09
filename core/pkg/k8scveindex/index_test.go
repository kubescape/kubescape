package k8scveindex

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFeed = `{
  "_kubernetes_io": {"updated_at": "2026-10-01T00:00:00Z"},
  "items": [
    {
      "id": "CVE-2024-3177",
      "summary": "Bypassing mountable secrets policy imposed by the ServiceAccount admission plugin",
      "content_text": "#### Affected Versions\n\n- kube-apiserver v1.29.0 - v1.29.3\n- kube-apiserver v1.28.0 - v1.28.8\n- kube-apiserver <= v1.27.12\n\n#### How do I mitigate"
    },
    {
      "id": "CVE-2023-3676",
      "summary": "Insufficient input sanitization on Windows nodes leads to privilege escalation",
      "content_text": "#### Affected Versions\n\n- kubelet <= v1.28.0\n- kubelet <= v1.27.4\n- kubelet <= v1.26.7\n"
    },
    {
      "id": "CVE-2021-25741",
      "summary": "Symlink Exchange Can Allow Host Filesystem Access",
      "content_text": "### Affected Versions\nv1.22.0 - v1.22.1\n\n<= v1.19.14\n"
    },
    {
      "id": "CVE-2020-8554",
      "summary": "Man in the middle using LoadBalancer or ExternalIPs",
      "content_text": "### Affected Components and Configurations\nAll Kubernetes versions are affected."
    }
  ]
}`

const embeddedFeedMaxAge = 30 * 24 * time.Hour

func embeddedFeedFresh(updatedAt, now time.Time) (time.Duration, bool) {
	age := now.Sub(updatedAt)
	return age, age >= 0 && age <= embeddedFeedMaxAge
}

func TestLookup(t *testing.T) {
	ix, err := Parse(strings.NewReader(testFeed))
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), ix.Updated)

	tests := []struct {
		cve, component, version, os string
		want                        Applicability
	}{
		{"CVE-2024-3177", "kube-apiserver", "1.28.4", "linux", Applicable},
		{"cve-2024-3177", "kube-apiserver", "v1.27.0", "linux", Applicable},
		{"CVE-2024-3177", "kube-apiserver", "1.28.9", "linux", NotApplicable},
		{"CVE-2024-3177", "kube-apiserver", "1.30.0", "linux", NotApplicable},
		{"CVE-2024-3177", "kubelet", "1.28.4", "linux", NotApplicable},
		{"CVE-2023-3676", "kubelet", "1.27.3", "linux", NotApplicable},
		{"CVE-2023-3676", "kubelet", "1.27.3", "windows", Applicable},
		{"CVE-2023-3676", "kubelet", "1.25.0", "Windows", Applicable},
		{"CVE-2023-3676", "kubelet", "1.27.10", "windows", NotApplicable},
		{"CVE-2023-3676", "kubelet", "1.28.1", "windows", NotApplicable},
		{"CVE-2021-25741", "kubelet", "1.22.0", "linux", Unattributed},
		{"CVE-2020-8554", "kube-apiserver", "1.28.4", "linux", Unattributed},
		{"CVE-2099-0001", "kubelet", "1.28.4", "linux", Unattributed},
		{"CVE-2024-3177", "kube-apiserver", "1.28", "linux", Unattributed},
		{"CVE-2024-3177", "kube-apiserver", "", "linux", Unattributed},
		{"CVE-2024-3177", "kube-apiserver", "1.28.4", "", Unattributed},
		{"CVE-2023-3676", "kubelet", "1.27.3", "", Unattributed},
		{"CVE-2023-3676", "kubelet", "1.27.3", "darwin", Unattributed},
		{"CVE-2024-3177", "kube-apiserver", "1.28.4", "Linux", Applicable},
	}

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.cve, tt.component, tt.version, tt.os}, "/"), func(t *testing.T) {
			assert.Equal(t, tt.want, ix.Lookup(tt.cve, tt.component, tt.version, tt.os))
		})
	}
}

func TestParseRejectsInvalidFeeds(t *testing.T) {
	for name, body := range map[string]string{
		"invalid json":   `{`,
		"no items":       `{"_kubernetes_io": {"updated_at": "2026-10-01T00:00:00Z"}, "items": []}`,
		"no update time": `{"items": [{"id": "CVE-2024-3177"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(body))
			assert.Error(t, err)
		})
	}
}

func TestEmbeddedFeed(t *testing.T) {
	ix, err := Parse(bytes.NewReader(embeddedFeed))
	require.NoError(t, err)

	assert.Equal(t, Applicable, ix.Lookup("CVE-2024-3177", "kube-apiserver", "1.28.4", "linux"))
	assert.Equal(t, NotApplicable, ix.Lookup("CVE-2024-3177", "kubelet", "1.28.4", "linux"))
	assert.Equal(t, NotApplicable, ix.Lookup("CVE-2023-3676", "kubelet", "1.27.3", "linux"))
	assert.Equal(t, NotApplicable, ix.Lookup("CVE-2023-5528", "kubelet", "1.27.3", "linux"))
	assert.Equal(t, Applicable, ix.Lookup("CVE-2023-5528", "kubelet", "1.27.3", "windows"))
	for _, v := range []string{"1.28.4", "1.27.8", "1.26.11", "1.25.16", "1.28.9"} {
		assert.Equal(t, NotApplicable, ix.Lookup("CVE-2023-5528", "kubelet", v, "windows"), v)
	}
	for _, v := range []string{"1.28.3", "1.27.7", "1.26.10", "1.25.15", "1.20.0"} {
		assert.Equal(t, Applicable, ix.Lookup("CVE-2023-5528", "kubelet", v, "windows"), v)
	}
	assert.Equal(t, Unattributed, ix.Lookup("CVE-2023-5528", "kubelet", "1.29.0", "windows"))
	assert.Equal(t, Applicable, ix.Lookup("CVE-2026-3288", "ingress-nginx", "1.14.3", "linux"))
	assert.Equal(t, NotApplicable, ix.Lookup("CVE-2026-3288", "ingress-nginx", "1.14.4", "linux"))
	assert.Equal(t, NotApplicable, ix.Lookup("CVE-2026-3288", "ingress-nginx", "1.15.0", "linux"))
}

func TestEmbeddedFeedFreshness(t *testing.T) {
	if os.Getenv("K8SCVEINDEX_CHECK_FEED_FRESHNESS") != "true" {
		t.Skip("set K8SCVEINDEX_CHECK_FEED_FRESHNESS=true to check embedded feed freshness")
	}

	ix, err := Parse(bytes.NewReader(embeddedFeed))
	require.NoError(t, err)

	now := time.Now()
	age, fresh := embeddedFeedFresh(ix.Updated, now)
	require.True(t, fresh,
		"embedded Kubernetes CVE feed is %s old (updated %s); run go generate ./core/pkg/k8scveindex; if the upstream updated_at is also stale, wait for an upstream update",
		age, ix.Updated.Format(time.RFC3339))

	futureAge, futureFresh := embeddedFeedFresh(now.Add(time.Second), now)
	assert.False(t, futureFresh, "future-dated feed should fail freshness check (age %s)", futureAge)
}

func TestEmbeddedFeedFreshnessDecision(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		updatedAt time.Time
		wantFresh bool
	}{
		{name: "current", updatedAt: now, wantFresh: true},
		{name: "maximum age", updatedAt: now.Add(-embeddedFeedMaxAge), wantFresh: true},
		{name: "stale", updatedAt: now.Add(-embeddedFeedMaxAge - time.Second), wantFresh: false},
		{name: "future", updatedAt: now.Add(time.Second), wantFresh: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, fresh := embeddedFeedFresh(tt.updatedAt, now)
			assert.Equal(t, tt.wantFresh, fresh)
		})
	}
}

func TestStale(t *testing.T) {
	updated := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ix := &Index{Updated: updated}
	week := DefaultMaxAge

	assert.False(t, ix.Stale(updated.Add(time.Hour), week, time.Time{}))
	assert.True(t, ix.Stale(updated.Add(8*24*time.Hour), week, time.Time{}))
	assert.False(t, ix.Stale(updated.Add(30*24*time.Hour), 0, time.Time{}))
	assert.True(t, ix.Stale(updated.Add(time.Hour), week, updated.Add(time.Minute)))
	assert.False(t, ix.Stale(updated.Add(time.Hour), week, updated.Add(-time.Hour)))
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	embedded, err := Parse(bytes.NewReader(embeddedFeed))
	require.NoError(t, err)

	serve := func(status int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}

	t.Run("remote", func(t *testing.T) {
		ix, src, err := Load(ctx, Options{URL: serve(http.StatusOK, testFeed)})
		require.NoError(t, err)
		assert.Equal(t, SourceRemote, src)
		assert.Equal(t, Applicable, ix.Lookup("CVE-2024-3177", "kube-apiserver", "1.28.4", "linux"))
	})

	for name, url := range map[string]string{
		"server error": serve(http.StatusInternalServerError, ""),
		"invalid body": serve(http.StatusOK, `<html>`),
		"unreachable":  "http://127.0.0.1:1",
	} {
		t.Run("falls back to embedded on "+name, func(t *testing.T) {
			ix, src, err := Load(ctx, Options{URL: url})
			require.NoError(t, err)
			assert.Equal(t, SourceEmbedded, src)
			assert.Equal(t, embedded.Updated, ix.Updated)
		})
	}

	t.Run("skip update uses embedded without fetching", func(t *testing.T) {
		var called bool
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		t.Cleanup(srv.Close)

		_, src, err := Load(ctx, Options{URL: srv.URL, SkipUpdate: true})
		require.NoError(t, err)
		assert.Equal(t, SourceEmbedded, src)
		assert.False(t, called)
	})

	t.Run("local path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "feed.json")
		require.NoError(t, os.WriteFile(path, []byte(testFeed), 0o600))

		ix, src, err := Load(ctx, Options{LocalPath: path, URL: "http://127.0.0.1:1"})
		require.NoError(t, err)
		assert.Equal(t, SourceLocal, src)
		assert.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), ix.Updated)
	})

	t.Run("unreadable local path is an error", func(t *testing.T) {
		_, _, err := Load(ctx, Options{LocalPath: filepath.Join(t.TempDir(), "missing.json")})
		assert.Error(t, err)

		path := filepath.Join(t.TempDir(), "feed.json")
		require.NoError(t, os.WriteFile(path, []byte(`{`), 0o600))
		_, _, err = Load(ctx, Options{LocalPath: path})
		assert.Error(t, err)
	})
}

func TestApplicabilityString(t *testing.T) {
	assert.Equal(t, "applicable", Applicable.String())
	assert.Equal(t, "not-applicable", NotApplicable.String())
	assert.Equal(t, "unattributed", Unattributed.String())
}
