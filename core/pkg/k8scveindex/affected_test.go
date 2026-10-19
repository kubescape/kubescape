package k8scveindex

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		in       string
		inside   []string
		outside  []string
		wantFail bool
	}{
		{in: "<= v1.27.12", inside: []string{"0.9.0", "1.0.0", "1.27.12"}, outside: []string{"1.27.13", "2.0.0"}},
		{in: "< v1.15.10", inside: []string{"1.15.9"}, outside: []string{"1.15.10"}},
		{in: "<=1.16.10", inside: []string{"1.16.10"}, outside: []string{"1.16.11"}},
		{in: "<= v1.30", inside: []string{"1.30.99"}, outside: []string{"1.31.0"}},
		{in: "< v1.31", inside: []string{"1.30.5"}, outside: []string{"1.31.0"}},
		{in: ">= v1.8.0", inside: []string{"1.8.0", "1.35.0"}, outside: []string{"1.7.9"}},
		{in: ">= v1.3", inside: []string{"1.3.0"}, outside: []string{"1.2.9"}},
		{in: "> v1.2.3", inside: []string{"1.2.4"}, outside: []string{"1.2.3"}},
		{in: "> v1.2", inside: []string{"1.3.0"}, outside: []string{"1.2.9"}},
		{in: "= v1.37.0", inside: []string{"1.37.0"}, outside: []string{"1.37.1", "1.36.9"}},
		{in: "v1.25.0", inside: []string{"1.25.0"}, outside: []string{"1.25.1"}},
		{in: "v1.25", inside: []string{"1.25.0", "1.25.7"}, outside: []string{"1.24.9", "1.26.0"}},
		{in: "v1.29.0 - v1.29.3", inside: []string{"1.29.0", "1.29.3"}, outside: []string{"1.28.9", "1.29.4"}},
		{in: "v1.18.0-1.18.5", inside: []string{"1.18.5"}, outside: []string{"1.18.6"}},
		{in: "v1.32.0 to v1.32.1", inside: []string{"1.32.1"}, outside: []string{"1.32.2"}},
		{in: `v1.11.0 \- 1.11.4`, inside: []string{"1.11.4"}, outside: []string{"1.11.5"}},
		{in: "v1.20 - v1.21", inside: []string{"1.20.0", "1.21.9"}, outside: []string{"1.19.9", "1.22.0"}},
		{in: "v2.0.0-alpha.0", wantFail: true},
		{in: "v1.29.3 - v1.29.0", wantFail: true},
		{in: "v1.22 - v1.21", wantFail: true},
		{in: "v1.21.5 - v1.21", inside: []string{"1.21.9"}, outside: []string{"1.21.4"}},
		{in: "v1.2.3 - v1.2.3", inside: []string{"1.2.3"}, outside: []string{"1.2.4"}},
		{in: "<= v1", wantFail: true},
		{in: "all versions", wantFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			r, err := parseRange(tt.in)
			if tt.wantFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, v := range tt.inside {
				assert.True(t, r.contains(mustVersion(t, v)), "%s should be in %s", v, tt.in)
			}
			for _, v := range tt.outside {
				assert.False(t, r.contains(mustVersion(t, v)), "%s should not be in %s", v, tt.in)
			}
		})
	}
}

func TestAffectedSection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
		found   bool
	}{
		{
			name:    "markdown heading",
			content: "intro\n\n#### Affected Versions\n\n- kubelet <= v1.28.0\n- kubelet <= v1.27.4\n\n### How do I mitigate\n- not this",
			want:    []string{"- kubelet <= v1.28.0", "- kubelet <= v1.27.4"},
			found:   true,
		},
		{
			name:    "bold heading with CRLF",
			content: "**Affected versions:**\r\n<= v1.15.9\r\n \r\n**How do I mitigate this vulnerability?**\r\nupgrade",
			want:    []string{"<= v1.15.9"},
			found:   true,
		},
		{
			name:    "empty section",
			content: "### Affected Versions\n\n### Fixed Versions\n- kubelet v1.28.1",
			found:   true,
		},
		{
			name:    "no section",
			content: "### Affected Components and Configurations\nAll Kubernetes versions are affected.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := affectedSection(tt.content)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseAffected(t *testing.T) {
	t.Run("components and prefixes", func(t *testing.T) {
		affected, err := parseAffected([]string{
			"- Kubernetes kube-apiserver <= v1.25.3",
			"kube-controller-manager: v1.19.0 - v1.19.2",
			"- kubelet/kube-proxy v1.18.0-1.18.3",
			"- kubelet >= v1.8.0 (including all later minor versions)",
		})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"kube-apiserver", "kube-controller-manager", "kubelet", "kube-proxy"}, keys(affected))
		assert.Len(t, affected["kubelet"], 2)
		assert.Len(t, affected["kube-proxy"], 1)
	})

	t.Run("one upper bound per minor is scoped to that minor", func(t *testing.T) {
		affected, err := parseAffected([]string{
			"kubelet: <= v1.34.11",
			"kubelet: <= v1.35.8",
			"kubelet: < v1.37.0",
			"kubelet: = v1.37.0",
		})
		require.NoError(t, err)
		inside := []string{"1.20.0", "1.34.11", "1.35.0", "1.35.8", "1.36.9", "1.37.0"}
		outside := []string{"1.34.12", "1.35.9", "1.37.1"}
		for _, v := range inside {
			assert.True(t, containsAny(affected["kubelet"], mustVersion(t, v)), v)
		}
		for _, v := range outside {
			assert.False(t, containsAny(affected["kubelet"], mustVersion(t, v)), v)
		}
	})

	t.Run("exclusive series start does not re-include fixed patches", func(t *testing.T) {
		affected, err := parseAffected([]string{
			"- ingress-nginx: < 1.13.8",
			"- ingress-nginx: < 1.14.4",
			"- ingress-nginx: < 1.15.0",
		})
		require.NoError(t, err)
		for _, v := range []string{"1.12.0", "1.13.7", "1.14.0", "1.14.3"} {
			assert.True(t, containsAny(affected["ingress-nginx"], mustVersion(t, v)), v)
		}
		for _, v := range []string{"1.13.8", "1.14.4", "1.14.9", "1.15.0"} {
			assert.False(t, containsAny(affected["ingress-nginx"], mustVersion(t, v)), v)
		}
	})

	for name, lines := range map[string][]string{
		"no lines":               nil,
		"no component":           {"v1.22.0 - v1.22.1"},
		"bare bound":             {"- < v1.11.0"},
		"generic kubernetes":     {"kubernetes v1.19.0 - v1.19.2"},
		"prose next to versions": {"The feature gate is enabled by default starting on version v1.31.", "- kube-controller-manager: <= v1.30.14"},
		"unparseable range":      {"- kubernetes-csi-proxy <= v2.0.0-alpha.0"},
		"unscopable major bound": {"- kubelet < v2.0.0", "- kubelet <= v1.5.3"},
		"reversed range":         {"- kube-apiserver v1.29.3 - v1.29.0"},
	} {
		t.Run(name, func(t *testing.T) {
			affected, err := parseAffected(lines)
			assert.Error(t, err)
			assert.Nil(t, affected)
		})
	}
}

func mustVersion(t *testing.T, s string) semver {
	t.Helper()
	v, full, err := parseVersion(s)
	require.NoError(t, err)
	require.True(t, full)
	return v
}

func containsAny(ranges []versionRange, v semver) bool {
	for _, r := range ranges {
		if r.contains(v) {
			return true
		}
	}
	return false
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
