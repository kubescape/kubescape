package locationresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bracketedKeyManifest carries the label and annotation keys the rules in the
// survey actually name, at known lines.
const bracketedKeyManifest = "apiVersion: apps/v1\n" + // 1
	"kind: Deployment\n" + // 2
	"metadata:\n" + // 3
	"  name: demo\n" + // 4
	"  labels:\n" + // 5
	"    app: demo\n" + // 6
	"    app.kubernetes.io/name: payments\n" + // 7
	"    pod-security.kubernetes.io/enforce: privileged\n" + // 8
	"  annotations:\n" + // 9
	"    kubernetes.io/ingress.class: nginx\n" + // 10
	"    service.beta.kubernetes.io/azure-load-balancer-internal: \"true\"\n" + // 11
	"    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: example-arn\n" + // 12
	"spec:\n" + // 13
	"  template:\n" + // 14
	"    metadata:\n" + // 15
	"      labels:\n" + // 16
	"        app: demo\n" + // 17
	"        app.kubernetes.io/name: payments\n" + // 18
	"    spec:\n" + // 19
	"      containers:\n" + // 20
	"        - name: api\n" + // 21
	"          image: nginx\n" // 22

// cronJobManifest carries the jobTemplate nesting two of the surveyed paths go
// through.
const cronJobManifest = "apiVersion: batch/v1\n" + // 1
	"kind: CronJob\n" + // 2
	"metadata:\n" + // 3
	"  name: nightly\n" + // 4
	"spec:\n" + // 5
	"  jobTemplate:\n" + // 6
	"    spec:\n" + // 7
	"      template:\n" + // 8
	"        metadata:\n" + // 9
	"          labels:\n" + // 10
	"            app.kubernetes.io/name: nightly\n" + // 11
	"        spec:\n" + // 12
	"          containers:\n" + // 13
	"            - name: job\n" + // 14
	"              image: busybox\n" // 15

func newResolverFor(t *testing.T, manifest string) *PathLocationResolver {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "d.yaml")
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0o600))
	resolver, err := NewPathLocationResolver(path)
	require.NoError(t, err)
	return resolver
}

// TestResolveLocation_SurveyedPaths covers all ten emitted paths the rule survey
// found unresolvable, verbatim from the rules' test fixtures. Each previously
// produced a yq parse error rather than a line, because the expression was
// built by prepending "." to the raw path and yq read the dots inside a label
// key as path separators.
//
// Two of the ten name a placeholder key, YOUR_LABEL, that a manifest never
// carries - they are fix paths for a label that has to be added. Those land on
// the enclosing labels map, the same walk-up any absent field gets.
func TestResolveLocation_SurveyedPaths(t *testing.T) {
	cases := []struct {
		rule     string
		manifest string
		path     string
		want     int
	}{
		// Keys carrying dots.
		{rule: "pod-security-admission-restricted-applied-2", manifest: bracketedKeyManifest, path: "metadata.labels[pod-security.kubernetes.io/enforce]", want: 8},
		{rule: "ingress-no-tls", manifest: bracketedKeyManifest, path: "metadata.annotations[kubernetes.io/ingress.class]", want: 10},
		{rule: "ensure-https-loadbalancers-encrypted-with-tls-azure", manifest: bracketedKeyManifest, path: "metadata.annotations[service.beta.kubernetes.io/azure-load-balancer-internal]", want: 11},
		{rule: "ensure-https-loadbalancers-encrypted-with-tls-aws", manifest: bracketedKeyManifest, path: "metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']", want: 12},
		{rule: "k8s-common-labels-usage", manifest: bracketedKeyManifest, path: "spec.template.metadata.labels[app.kubernetes.io/name]", want: 18},
		{rule: "k8s-common-labels-usage", manifest: cronJobManifest, path: "spec.jobTemplate.spec.template.metadata.labels[app.kubernetes.io/name]", want: 11},
		// Plain keys.
		{rule: "label-usage-for-resources", manifest: bracketedKeyManifest, path: "metadata.labels[app]", want: 6},
		{rule: "label-usage-for-resources", manifest: bracketedKeyManifest, path: "spec.template.metadata.labels[app]", want: 17},
		// Placeholder keys: absent, so they land on the labels map.
		{rule: "label-usage-for-resources", manifest: bracketedKeyManifest, path: "metadata.labels[YOUR_LABEL]", want: 6},
		{rule: "label-usage-for-resources", manifest: cronJobManifest, path: "spec.jobTemplate.spec.template.metadata.labels[YOUR_LABEL]", want: 11},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			location, err := newResolverFor(t, tc.manifest).ResolveLocation(tc.path, 0)
			require.NoError(t, err)
			assert.Equal(t, tc.want, location.Line, "path emitted by %s", tc.rule)
		})
	}
}

// TestResolveLocation_BracketedKeySpellings covers the other ways the same key
// can be written, which must all land on the same line.
func TestResolveLocation_BracketedKeySpellings(t *testing.T) {
	resolver := newResolverFor(t, bracketedKeyManifest)

	for _, path := range []string{
		"metadata.annotations[kubernetes.io/ingress.class]",
		"metadata.annotations['kubernetes.io/ingress.class']",
		`metadata.annotations["kubernetes.io/ingress.class"]`,
		// A fix path arrives as "<path>=<value>"; only the path half selects.
		"metadata.annotations[kubernetes.io/ingress.class]=nginx",
	} {
		t.Run(path, func(t *testing.T) {
			location, err := resolver.ResolveLocation(path, 0)
			require.NoError(t, err)
			assert.Equal(t, 10, location.Line)
		})
	}
}

// TestResolveLocation_BracketedKeyWalksUp covers a bracketed key that is absent,
// which is the normal shape of a fix that adds a label. Walking up now drops a
// whole segment, so it lands on the enclosing map rather than peeling the key
// apart one dotted fragment at a time.
func TestResolveLocation_BracketedKeyWalksUp(t *testing.T) {
	resolver := newResolverFor(t, bracketedKeyManifest)

	for _, path := range []string{
		"metadata.labels[app.kubernetes.io/absent]",
		"metadata.labels[absent]",
		"metadata.annotations['not.a.real/key']",
	} {
		t.Run(path, func(t *testing.T) {
			location, err := resolver.ResolveLocation(path, 0)
			require.NoError(t, err)
			assert.NotZero(t, location.Line, "an absent key should land on its parent block")
		})
	}
}

// TestResolveLocation_KeysNeedingEscapes covers keys carrying the characters
// that would otherwise end the rendered expression's quoted key early and leave
// the rest to be read as yq syntax.
//
// Kubernetes cannot produce these - a label or annotation key must match
// [a-zA-Z0-9]([-a-zA-Z0-9_.]*[a-zA-Z0-9])? with an optional DNS-subdomain
// prefix - so what is pinned is that such input is either read exactly or
// refused, never approximated.
func TestResolveLocation_KeysNeedingEscapes(t *testing.T) {
	manifest := "metadata:\n" + // 1
		"  annotations:\n" + // 2
		"    with\"quote: a\n" + // 3
		"    plain: b\n" // 4

	resolver := newResolverFor(t, manifest)

	t.Run("double quote in a single-quoted key is escaped and resolves", func(t *testing.T) {
		location, err := resolver.ResolveLocation(`metadata.annotations.'with"quote'`, 0)
		require.NoError(t, err)
		assert.Equal(t, 3, location.Line)
	})

	t.Run("backslash in a key does not error or mis-resolve", func(t *testing.T) {
		location, err := resolver.ResolveLocation(`metadata.annotations[with\backslash]`, 0)
		require.NoError(t, err)
		assert.NotEqual(t, 4, location.Line, "must not resolve to a different key")
	})

	// Expression syntax smuggled into a key is refused by the parser before
	// any expression is built, so it never reaches yq at all.
	for _, path := range []string{
		`metadata.annotations[with"quote]`,
		`metadata.annotations["] | .metadata]`,
	} {
		t.Run("refused: "+path, func(t *testing.T) {
			location, err := resolver.ResolveLocation(path, 0)
			assert.ErrorIs(t, err, pathparse.ErrMalformedPath)
			assert.Equal(t, Location{}, location)
		})
	}
}

// TestResolveLocation_DotQuotedKeyWithPrecedingSibling covers the spelling
// kubescape fix already uses for a key holding dots. Split at the dot inside
// its quotes, the key is not found and walking up lands on the annotations
// map - whose line is that of its first entry, a sibling the path never named.
// The sibling here is placed first so that wrong answer is distinguishable
// from the right one.
func TestResolveLocation_DotQuotedKeyWithPrecedingSibling(t *testing.T) {
	manifest := "metadata:\n" + // 1
		"  annotations:\n" + // 2
		"    other.io/first: a\n" + // 3
		"    foo.bar/baz: b\n" // 4

	resolver := newResolverFor(t, manifest)

	for _, path := range []string{
		`metadata.annotations."foo.bar/baz"`,
		`metadata.annotations.'foo.bar/baz'`,
		`metadata.annotations."foo.bar/baz"=hello`,
	} {
		t.Run(path, func(t *testing.T) {
			location, err := resolver.ResolveLocation(path, 0)
			require.NoError(t, err)
			assert.Equal(t, 4, location.Line, "must point at foo.bar/baz, not the sibling above it")
		})
	}
}

// TestResolveLocation_MalformedPathIsRejectedBeforeWalkingUp covers paths that
// are not well formed but whose nearest well-formed reading exists in the
// manifest. Each used to resolve to a real line with no error. Walking up is
// for a well-formed path whose field is absent; a path that cannot be read has
// to be refused first, or an ancestor's line is reported as the finding's.
func TestResolveLocation_MalformedPathIsRejectedBeforeWalkingUp(t *testing.T) {
	manifest := "metadata:\n" + // 1
		"  labels:\n" + // 2
		"    app: demo\n" + // 3
		"spec:\n" + // 4
		"  image: nginx\n" + // 5
		"  containers:\n" + // 6
		"    - name: a\n" + // 7
		"      image: one\n" // 8

	resolver := newResolverFor(t, manifest)

	for _, path := range []string{
		"metadata.labels[app",   // unclosed bracket; "app" exists
		"metadata.labels]",      // stray ']'; "labels" exists
		"spec..image",           // doubled '.'; "spec.image" exists
		"spec.image.",           // trailing '.'
		"metadata.labels[].app", // empty brackets
		"spec[*].image",         // wildcard on a map
		"spec.containers[0][1]", // second index
		`metadata.labels."app`,  // unclosed quote
	} {
		t.Run(path, func(t *testing.T) {
			location, err := resolver.ResolveLocation(path, 0)
			assert.ErrorIs(t, err, pathparse.ErrMalformedPath)
			assert.Equal(t, Location{}, location)
		})
	}
}
