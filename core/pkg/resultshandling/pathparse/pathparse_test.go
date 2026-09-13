package pathparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func seg(key string, index int) Segment {
	return Segment{Key: key, Index: index}
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
		want []Segment
	}{
		// Keys carrying dots. A "."-split shattered these into fragments that
		// matched nothing.
		{
			name: "pod security admission label",
			rule: "pod-security-admission-restricted-applied-2",
			path: "metadata.labels[pod-security.kubernetes.io/enforce]",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("pod-security.kubernetes.io/enforce", -1)},
		},
		{
			name: "ingress class annotation",
			rule: "ingress-no-tls",
			path: "metadata.annotations[kubernetes.io/ingress.class]",
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("kubernetes.io/ingress.class", -1)},
		},
		{
			name: "azure internal load balancer annotation",
			rule: "ensure-https-loadbalancers-encrypted-with-tls-azure",
			path: "metadata.annotations[service.beta.kubernetes.io/azure-load-balancer-internal]",
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("service.beta.kubernetes.io/azure-load-balancer-internal", -1)},
		},
		{
			// Dotted and quoted at once, the only emitted path that is both.
			name: "aws ssl cert annotation is quoted and dotted",
			rule: "ensure-https-loadbalancers-encrypted-with-tls-aws",
			path: "metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']",
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("service.beta.kubernetes.io/aws-load-balancer-ssl-cert", -1)},
		},
		{
			name: "common label through a pod template",
			rule: "k8s-common-labels-usage",
			path: "spec.template.metadata.labels[app.kubernetes.io/name]",
			want: []Segment{seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app.kubernetes.io/name", -1)},
		},
		{
			name: "common label through a CronJob job template",
			rule: "k8s-common-labels-usage",
			path: "spec.jobTemplate.spec.template.metadata.labels[app.kubernetes.io/name]",
			want: []Segment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app.kubernetes.io/name", -1)},
		},

		// Plain keys. Nothing shattered here, which is what made these worse:
		// the bracket was dropped and the path resolved to the whole labels
		// map, reading as a successful lookup of the wrong field.
		{
			name: "plain label key is kept, not dropped",
			rule: "label-usage-for-resources",
			path: "metadata.labels[app]",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "placeholder label key is kept, not dropped",
			rule: "label-usage-for-resources",
			path: "metadata.labels[YOUR_LABEL]",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("YOUR_LABEL", -1)},
		},
		{
			name: "plain label key through a pod template",
			rule: "label-usage-for-resources",
			path: "spec.template.metadata.labels[app]",
			want: []Segment{seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "placeholder label key through a CronJob job template",
			rule: "label-usage-for-resources",
			path: "spec.jobTemplate.spec.template.metadata.labels[YOUR_LABEL]",
			want: []Segment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("metadata", -1), seg("labels", -1), seg("YOUR_LABEL", -1)},
		},
		{
			// Secret data keys arrive bracketed too, and their names are
			// exactly what the credential patterns look for.
			name: "secret data key",
			rule: "rule-credentials-in-env-var",
			path: "data[aws_access_key_id]",
			want: []Segment{seg("data", -1), seg("aws_access_key_id", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePath(tc.path), "path emitted by %s", tc.rule)
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
		want []Segment
	}{
		{
			name: "container index",
			path: "spec.containers[0].image",
			want: []Segment{seg("spec", -1), seg("containers", 0), seg("image", -1)},
		},
		{
			name: "two indexes in one path",
			path: "spec.containers[1].env[2].value",
			want: []Segment{seg("spec", -1), seg("containers", 1), seg("env", 2), seg("value", -1)},
		},
		{
			name: "indexed segment at the end",
			path: "spec.containers[0]",
			want: []Segment{seg("spec", -1), seg("containers", 0)},
		},
		{
			name: "projected volume source keeps both indexes",
			path: "spec.volumes[0].projected.sources[0].serviceAccountToken",
			want: []Segment{seg("spec", -1), seg("volumes", 0), seg("projected", -1), seg("sources", 0), seg("serviceAccountToken", -1)},
		},
		{
			// A non-numeric bracket is a key, so it becomes its own segment
			// rather than an index. The lookup then finds nothing on a list,
			// which is the honest answer.
			name: "non-numeric bracket is a key, not an index",
			path: "spec.containers[container_ndx].image",
			want: []Segment{seg("spec", -1), seg("containers", -1), seg("container_ndx", -1), seg("image", -1)},
		},
		{
			name: "negative index is treated as a key",
			path: "spec.containers[-1].image",
			want: []Segment{seg("spec", -1), seg("containers", -1), seg("-1", -1), seg("image", -1)},
		},
		{
			// An index can follow a bracketed key, and it qualifies that key.
			// Dropping it would resolve the path to the whole list - the same
			// "succeeds against the wrong thing" failure reading brackets
			// exists to end.
			name: "index following a bracketed key qualifies it",
			path: "metadata.annotations[foo.bar/list][2]",
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("foo.bar/list", 2)},
		},
		{
			name: "index following a bracketed key mid-path",
			path: "metadata.annotations[foo.bar/list][2].name",
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("foo.bar/list", 2), seg("name", -1)},
		},
		{
			// A second index has nothing left to qualify: the segment already
			// carries one. Kubernetes has no nested lists here, so this is
			// malformed input rather than a shape to support.
			name: "a second index on an already-indexed segment is dropped",
			path: "spec.containers[0][1]",
			want: []Segment{seg("spec", -1), seg("containers", 0)},
		},
		{
			// Quoting is how a rule says "key, not index". Stripping the quotes
			// before testing for digits would throw that signal away.
			name: "quoted digits stay a key",
			path: "data['0']",
			want: []Segment{seg("data", -1), seg("0", -1)},
		},
		{
			name: "double-quoted digits stay a key",
			path: `data["12"]`,
			want: []Segment{seg("data", -1), seg("12", -1)},
		},
		{
			// strconv.Atoi accepts a sign; a list index never carries one.
			name: "signed digits are a key, not an index",
			path: "data[+0]",
			want: []Segment{seg("data", -1), seg("+0", -1)},
		},
		{
			name: "leading zeros are still digits",
			path: "spec.containers[007].image",
			want: []Segment{seg("spec", -1), seg("containers", 7), seg("image", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePath(tc.path))
		})
	}
}

// TestParsePath_ValueSeparator covers the "<path>=<value>" form that
// assisted-remediation strings arrive in.
func TestParsePath_ValueSeparator(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []Segment
	}{
		{
			name: "value is dropped",
			path: "spec.hostPID=false",
			want: []Segment{seg("spec", -1), seg("hostPID", -1)},
		},
		{
			// CIS control-plane rules emit values that contain "=" themselves,
			// so the split has to be on the first separator.
			name: "only the first separator splits",
			path: "spec.containers[0].command=--anonymous-auth=false",
			want: []Segment{seg("spec", -1), seg("containers", 0), seg("command", -1)},
		},
		{
			// An "=" inside a bracket is part of the key.
			name: "separator inside a bracket is part of the key",
			path: "metadata.labels[a=b]=c",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("a=b", -1)},
		},
		{
			name: "leading dot is trimmed",
			path: ".spec.nodeName",
			want: []Segment{seg("spec", -1), seg("nodeName", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePath(tc.path))
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
		want []Segment
	}{
		{name: "empty path", path: "", want: nil},
		{name: "only a dot", path: ".", want: nil},
		{name: "doubled dots are skipped", path: "spec..image", want: []Segment{seg("spec", -1), seg("image", -1)}},
		{name: "trailing dot", path: "spec.image.", want: []Segment{seg("spec", -1), seg("image", -1)}},
		{
			name: "unclosed bracket takes the rest of the string",
			path: "metadata.labels[app",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "empty brackets contribute nothing",
			path: "metadata.labels[].app",
			want: []Segment{seg("metadata", -1), seg("labels", -1), seg("app", -1)},
		},
		{
			name: "leading index has nothing to qualify",
			path: "[0].spec",
			want: []Segment{seg("spec", -1)},
		},
		{
			name: "double-quoted key is unquoted like a single-quoted one",
			path: `metadata.annotations["a.b/c"]`,
			want: []Segment{seg("metadata", -1), seg("annotations", -1), seg("a.b/c", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePath(tc.path))
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
		want []Segment
	}{
		{
			path: "spec.automountServiceAccountToken",
			want: []Segment{seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.template.spec.automountServiceAccountToken",
			want: []Segment{seg("spec", -1), seg("template", -1), seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.jobTemplate.spec.template.spec.automountServiceAccountToken",
			want: []Segment{seg("spec", -1), seg("jobTemplate", -1), seg("spec", -1), seg("template", -1), seg("spec", -1), seg("automountServiceAccountToken", -1)},
		},
		{
			path: "spec.volumes[0].secret.secretName",
			want: []Segment{seg("spec", -1), seg("volumes", 0), seg("secret", -1), seg("secretName", -1)},
		},
		{
			path: "spec.volumes[0].projected.sources[0].serviceAccountToken.tokenExpirationSeconds",
			want: []Segment{seg("spec", -1), seg("volumes", 0), seg("projected", -1), seg("sources", 0), seg("serviceAccountToken", -1), seg("tokenExpirationSeconds", -1)},
		},
		{
			path: "spec.tls[0].secretName",
			want: []Segment{seg("spec", -1), seg("tls", 0), seg("secretName", -1)},
		},
		{
			path: "automountServiceAccountToken",
			want: []Segment{seg("automountServiceAccountToken", -1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePath(tc.path))
		})
	}
}

// TestBracketedKeyIsResolved covers what reading the bracket buys: the value at
// the key the path names, rather than the map containing it. Dropping the
// bracket did not fail - it returned the whole map, which reads as a successful
// lookup of the wrong field.
