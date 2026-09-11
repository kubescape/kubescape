package printer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func seg(key string, index int) pathSegment {
	return pathSegment{key: key, index: index}
}

// TestParsePath_EmittedByRules covers every path shape a regolibrary rule
// actually emits that the previous "."-splitting parser could not read. The
// inputs are taken verbatim from the rules' own test fixtures, so they are the
// substituted output rather than the sprintf templates in raw.rego.
func TestParsePath_EmittedByRules(t *testing.T) {
	cases := []struct {
		name string
		rule string
		path string
		want []pathSegment
	}{
		// Keys carrying dots. A "."-split shattered these into fragments that
		// matched nothing.
		{
			name: "pod security admission label",
			rule: "pod-security-admission-restricted-applied-2",
			path: "metadata.labels[pod-security.kubernetes.io/enforce]",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("pod-security.kubernetes.io/enforce", -1)},
		},
		{
			name: "ingress class annotation",
			rule: "ingress-no-tls",
			path: "metadata.annotations[kubernetes.io/ingress.class]",
			want: []pathSegment{seg("metadata", -1), seg("annotations", -1), seg("kubernetes.io/ingress.class", -1)},
		},
		{
			name: "azure internal load balancer annotation",
			rule: "ensure-https-loadbalancers-encrypted-with-tls-azure",
			path: "metadata.annotations[service.beta.kubernetes.io/azure-load-balancer-internal]",
			want: []pathSegment{seg("metadata", -1), seg("annotations", -1), seg("service.beta.kubernetes.io/azure-load-balancer-internal", -1)},
		},
		{
			// Dotted and quoted at once, the only emitted path that is both.
			name: "aws ssl cert annotation is quoted and dotted",
			rule: "ensure-https-loadbalancers-encrypted-with-tls-aws",
			path: "metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']",
			want: []pathSegment{seg("metadata", -1), seg("annotations", -1), seg("service.beta.kubernetes.io/aws-load-balancer-ssl-cert", -1)},
		},
		{
			name: "common label through a pod template",
			rule: "k8s-common-labels-usage",
			path: "spec.template.metadata.labels[app.kubernetes.io/name]",
			want: []pathSegment{seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app.kubernetes.io/name", -1)},
		},
		{
			name: "common label through a CronJob job template",
			rule: "k8s-common-labels-usage",
			path: "spec.jobTemplate.spec.template.metadata.labels[app.kubernetes.io/name]",
			want: []pathSegment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app.kubernetes.io/name", -1)},
		},

		// Plain keys. Nothing shattered here, which is what made these worse:
		// the bracket was dropped and the path resolved to the whole labels
		// map, reading as a successful lookup of the wrong field.
		{
			name: "plain label key is kept, not dropped",
			rule: "label-usage-for-resources",
			path: "metadata.labels[app]",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "placeholder label key is kept, not dropped",
			rule: "label-usage-for-resources",
			path: "metadata.labels[YOUR_LABEL]",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("YOUR_LABEL", -1)},
		},
		{
			name: "plain label key through a pod template",
			rule: "label-usage-for-resources",
			path: "spec.template.metadata.labels[app]",
			want: []pathSegment{seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "placeholder label key through a CronJob job template",
			rule: "label-usage-for-resources",
			path: "spec.jobTemplate.spec.template.metadata.labels[YOUR_LABEL]",
			want: []pathSegment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("YOUR_LABEL", -1)},
		},
		{
			// Secret data keys arrive bracketed too, and their names are
			// exactly what the credential patterns look for.
			name: "secret data key",
			rule: "rule-credentials-in-env-var",
			path: "data[aws_access_key_id]",
			want: []pathSegment{seg("data", -1), seg("aws_access_key_id", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePath(tc.path), "path emitted by %s", tc.rule)
		})
	}
}

// TestParsePath_IndexBelongsToItsSegment pins the shape callers depend on: an
// index qualifies the segment it follows rather than standing alone. Splitting
// it out would shift every parent path by one and unmatch the safe-field rules
// that gate redaction.
func TestParsePath_IndexBelongsToItsSegment(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []pathSegment
	}{
		{
			name: "container index",
			path: "spec.containers[0].image",
			want: []pathSegment{seg("spec", -1), seg("containers", 0), seg("image", -1)},
		},
		{
			name: "two indexes in one path",
			path: "spec.containers[1].env[2].value",
			want: []pathSegment{seg("spec", -1), seg("containers", 1), seg("env", 2), seg("value", -1)},
		},
		{
			name: "indexed segment at the end",
			path: "spec.containers[0]",
			want: []pathSegment{seg("spec", -1), seg("containers", 0)},
		},
		{
			name: "projected volume source keeps both indexes",
			path: "spec.volumes[0].projected.sources[0].serviceAccountToken",
			want: []pathSegment{seg("spec", -1), seg("volumes", 0), seg("projected", -1), seg("sources", 0), seg("serviceAccountToken", -1)},
		},
		{
			// A non-numeric bracket is a key, so it becomes its own segment
			// rather than an index. The lookup then finds nothing on a list,
			// which is the honest answer.
			name: "non-numeric bracket is a key, not an index",
			path: "spec.containers[container_ndx].image",
			want: []pathSegment{seg("spec", -1), seg("containers", -1), seg("container_ndx", -1), seg("image", -1)},
		},
		{
			name: "negative index is treated as a key",
			path: "spec.containers[-1].image",
			want: []pathSegment{seg("spec", -1), seg("containers", -1), seg("-1", -1), seg("image", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePath(tc.path))
		})
	}
}

// TestParsePath_ValueSeparator covers the "<path>=<value>" form that
// assisted-remediation strings arrive in.
func TestParsePath_ValueSeparator(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []pathSegment
	}{
		{
			name: "value is dropped",
			path: "spec.hostPID=false",
			want: []pathSegment{seg("spec", -1), seg("hostPID", -1)},
		},
		{
			// CIS control-plane rules emit values that contain "=" themselves,
			// so the split has to be on the first separator.
			name: "only the first separator splits",
			path: "spec.containers[0].command=--anonymous-auth=false",
			want: []pathSegment{seg("spec", -1), seg("containers", 0), seg("command", -1)},
		},
		{
			// An "=" inside a bracket is part of the key.
			name: "separator inside a bracket is part of the key",
			path: "metadata.labels[a=b]=c",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("a=b", -1)},
		},
		{
			name: "leading dot is trimmed",
			path: ".spec.nodeName",
			want: []pathSegment{seg("spec", -1), seg("nodeName", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePath(tc.path))
		})
	}
}

// TestParsePath_Malformed covers input the scanner does not control. These
// paths come from rules, so the parser reads what it can rather than rejecting:
// a path resolving to nothing is already handled by every caller.
func TestParsePath_Malformed(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []pathSegment
	}{
		{name: "empty path", path: "", want: nil},
		{name: "only a dot", path: ".", want: nil},
		{name: "doubled dots are skipped", path: "spec..image", want: []pathSegment{seg("spec", -1), seg("image", -1)}},
		{name: "trailing dot", path: "spec.image.", want: []pathSegment{seg("spec", -1), seg("image", -1)}},
		{
			name: "unclosed bracket takes the rest of the string",
			path: "metadata.labels[app",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "empty brackets contribute nothing",
			path: "metadata.labels[].app",
			want: []pathSegment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "leading index has nothing to qualify",
			path: "[0].spec",
			want: []pathSegment{seg("spec", -1)},
		},
		{
			name: "double-quoted key is unquoted like a single-quoted one",
			path: `metadata.annotations["a.b/c"]`,
			want: []pathSegment{seg("metadata", -1), seg("annotations", -1), seg("a.b/c", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePath(tc.path))
		})
	}
}

// TestParsePath_SafeFieldPathsAreUnchanged is the redaction guard. matchesSafeField
// compares a field's parents positionally against the canonical location its
// Kubernetes schema defines, so if any of these paths parsed differently after
// this change, the kind/path scoping protecting credential redaction would
// silently loosen.
func TestParsePath_SafeFieldPathsAreUnchanged(t *testing.T) {
	cases := []struct {
		path string
		want []pathSegment
	}{
		{
			path: "spec.automountServiceAccountToken",
			want: []pathSegment{seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.template.spec.automountServiceAccountToken",
			want: []pathSegment{seg("spec", -1), seg("template", -1), seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.jobTemplate.spec.template.spec.automountServiceAccountToken",
			want: []pathSegment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.volumes[0].secret.secretName",
			want: []pathSegment{seg("spec", -1), seg("volumes", 0), seg("secret", -1), seg("secretName", -1)},
		},
		{
			path: "spec.volumes[0].projected.sources[0].serviceAccountToken.tokenExpirationSeconds",
			want: []pathSegment{seg("spec", -1), seg("volumes", 0), seg("projected", -1), seg("sources", 0), seg("serviceAccountToken", -1), seg("tokenExpirationSeconds", -1)},
		},
		{
			path: "spec.tls[0].secretName",
			want: []pathSegment{seg("spec", -1), seg("tls", 0), seg("secretName", -1)},
		},
		{
			path: "automountServiceAccountToken",
			want: []pathSegment{seg("automountServiceAccountToken", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePath(tc.path))
		})
	}
}

// TestBracketedKeyIsResolved covers what reading the bracket buys: the value at
// the key the path names, rather than the map containing it. Dropping the
// bracket did not fail - it returned the whole map, which reads as a successful
// lookup of the wrong field.
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSensitivePath(tc.kind, tc.path))
		})
	}
}
