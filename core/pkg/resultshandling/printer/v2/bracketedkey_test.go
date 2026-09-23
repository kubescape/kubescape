package printer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBracketedKeyIsResolved(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				"app":                                "payments-api",
				"app.kubernetes.io/name":             "payments",
				"pod-security.kubernetes.io/enforce": "privileged",
			},
		},
	}

	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "plain key", path: "metadata.labels[app]", want: "payments-api"},
		{name: "dotted key", path: "metadata.labels[app.kubernetes.io/name]", want: "payments"},
		{name: "pod security label", path: "metadata.labels[pod-security.kubernetes.io/enforce]", want: "privileged"},
		{name: "quoted key", path: "metadata.labels['app']", want: "payments-api"},
		{name: "path with a value suffix", path: "metadata.labels[app]=YOUR_VALUE", want: "payments-api"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractValueAtPath(obj, tc.path)
			assert.True(t, ok, "path should resolve")
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("absent key resolves to nothing rather than the whole map", func(t *testing.T) {
		_, ok := extractValueAtPath(obj, "metadata.labels[absent]")
		assert.False(t, ok)
	})
}

// TestBracketedKeyRedaction documents the redaction change reading the bracket
// causes, and is the reason this is not a behaviour-neutral refactor.
//
// The field name isSensitivePath tests is the path's last segment. While the
// bracket was dropped that was the container - "labels", "data" - which is
// never credential-shaped, so a bracketed key holding a credential was printed
// in full. Reading the bracket makes the key itself the last segment, so the
// name that gets tested is the one that actually describes the value.
func TestBracketedKeyRedaction(t *testing.T) {
	cases := []struct {
		name string
		kind string
		path string
		want bool
	}{
		{
			// Emitted by the credentials-in-env-var rules against Secret data.
			name: "secret data key named like a credential is redacted",
			kind: "Secret",
			path: "data[aws_access_key_id]",
			want: true,
		},
		{
			name: "secret data key named like a password is redacted",
			kind: "Secret",
			path: "data[pwd]",
			want: true,
		},
		{
			name: "credential-shaped label key is redacted on any kind",
			kind: "Deployment",
			path: "metadata.labels[apiKey]",
			want: true,
		},
		{
			// The change only reaches keys that are credential-shaped. An
			// ordinary label key stays visible, which is what makes the
			// evidence useful.
			name: "ordinary label key is still shown",
			kind: "Deployment",
			path: "metadata.labels[app]",
			want: false,
		},
		{
			name: "common label key is still shown",
			kind: "Deployment",
			path: "spec.template.metadata.labels[app.kubernetes.io/name]",
			want: false,
		},
		// Everything under a Secret's data is sensitive whatever the key is
		// called. A bracketed key does not start with "data.", so the prefix
		// test that used to gate this let any key through whose own name was
		// not credential-shaped.
		{
			name: "secret data key with an ordinary name is still redacted",
			kind: "Secret",
			path: "data[username]",
			want: true,
		},
		{
			name: "secret stringData key with an ordinary name is still redacted",
			kind: "Secret",
			path: "stringData[config]",
			want: true,
		},
		{
			name: "quoted secret data key is redacted",
			kind: "Secret",
			path: "data['username']",
			want: true,
		},
		{
			name: "dotted secret data key is redacted",
			kind: "Secret",
			path: "data[my.config.file]",
			want: true,
		},
		{
			name: "dotted secret data path is still redacted",
			kind: "Secret",
			path: "data.username",
			want: true,
		},
		{
			// The Secret exception is scoped to its content, not to the kind.
			name: "secret metadata is not redacted",
			kind: "Secret",
			path: "metadata.name",
			want: false,
		},
		{
			// A field merely starting with the same letters is not Secret data.
			name: "a field named like data is not Secret data",
			kind: "Secret",
			path: "dataSomethingElse",
			want: false,
		},
		{
			name: "an ordinary key on a non-Secret kind is unaffected",
			kind: "ConfigMap",
			path: "data[username]",
			want: false,
		},
		// A container env value has several spellings. Extraction resolves all
		// of them, so classification has to recognise all of them: one it
		// misses is a credential printed without --show-secrets.
		{
			name: "env value, plain spelling",
			kind: "Deployment",
			path: "spec.containers[0].env[1].value",
			want: true,
		},
		{
			name: "env value, single-quoted bracket spelling",
			kind: "Deployment",
			path: "spec.containers[0]['env'][1].value",
			want: true,
		},
		{
			name: "env value, double-quoted bracket spelling",
			kind: "Deployment",
			path: `spec.containers[0]["env"][1].value`,
			want: true,
		},
		{
			name: "env value through a pod template",
			kind: "Deployment",
			path: "spec.template.spec.initContainers[0]['env'][0].value",
			want: true,
		},
		{
			// The name of an env var is not its value, in any spelling.
			name: "env name is not a value",
			kind: "Deployment",
			path: "spec.containers[0]['env'][1].name",
			want: false,
		},
		{
			// valueFrom is a reference; the Secret it names is redacted by kind.
			name: "env valueFrom is a reference, not a literal",
			kind: "Deployment",
			path: "spec.containers[0]['env'][0].valueFrom.secretKeyRef.name",
			want: false,
		},
		{
			// Without an index this is not an element of the env list.
			name: "env without an index is not an env value",
			kind: "Deployment",
			path: "spec.containers[0].env.value",
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSensitivePath(tc.kind, tc.path))
		})
	}
}
