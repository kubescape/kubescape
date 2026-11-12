package opaprocessor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func regoModule(body string) string {
	return "package armo_builtins\nimport rego.v1\n\n" + body
}

func TestRegoSourceIsHermetic(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		hermetic bool
	}{
		{
			name:     "a rule reading only its input element",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: true,
		},
		{
			name:     "a deterministic library call",
			source:   regoModule("import data.cautils\n\ndeny contains msga if {\n\tpod := input[_]\n\tcautils.list_contains([\"a\"], pod.metadata.name)\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: true,
		},
		{
			name:     "the allowlisted image name builtin",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\timage.parse_normalized_name(pod.spec.containers[_].image) != \"\"\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: true,
		},
		{
			// ensure-https-loadbalancers-encrypted-with-tls-aws imports the
			// API client without calling it.
			name:     "importing the API client library without calling it",
			source:   regoModule("import data.kubernetes.api.client\n\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: true,
		},
		{
			name:     "a library value that is a base document",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tdata.kubernetes.api.client.host == pod.spec.host\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: true,
		},
		{
			name:     "the current time",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\ttime.now_ns() > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a registry signature lookup",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tnot cosign.has_signature(pod.spec.containers[_].image)\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a JSON schema that may be fetched",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\t[ok, _] := json.match_schema(pod, {\"$ref\": \"https://example.com/s.json\"})\n\tnot ok\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "certificate verification against the current time",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\t[ok, _] := crypto.x509.parse_and_verify_certificates(pod.data.crt)\n\tnot ok\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a local helper function",
			source:   regoModule("signed(image) if cosign.has_signature(image)\n\ndeny contains msga if {\n\tpod := input[_]\n\tnot signed(pod.spec.containers[_].image)\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a helper rule deny does not refer to, evaluated with the package",
			source:   regoModule("now := time.now_ns()\n\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a library function through an import alias",
			source:   regoModule("import data.kubernetes.api.client as k8s\n\ndeny contains msga if {\n\tpod := input[_]\n\tk8s.query_all(\"pods\").status_code == 200\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a library function through its full reference",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tdata.kubernetes.api.client.query_all(\"pods\").status_code == 200\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a library function inside a comprehension",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tr := [s | s := data.kubernetes.api.client.query_all(\"pods\")]\n\tcount(r) > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a dynamic reference into a library package",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tsome k\n\tdata.kubernetes.api[k]\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a fully dynamic data reference",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tsome a, b\n\tdata[a][b]\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "an else branch reaching a helper rule",
			source:   regoModule("h := time.now_ns()\n\nv := 1 if {\n\tfalse\n} else := h\n\ndeny contains msga if {\n\tpod := input[_]\n\tv > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a function else branch",
			source:   regoModule("f(_) := 1 if {\n\tfalse\n} else := rand.intn(\"k\", 10)\n\ndeny contains msga if {\n\tpod := input[_]\n\tf(pod) > 100\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a general reference head",
			source:   regoModule("p[k].y := time.now_ns() if k := \"a\"\n\ndeny contains msga if {\n\tpod := input[_]\n\tp.a.y > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "an every block calling a helper",
			source:   regoModule("g(c) if uuid.rfc4122(c) != \"\"\n\ndeny contains msga if {\n\tpod := input[_]\n\tevery c in pod.spec.containers {\n\t\tg(c.name)\n\t}\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a with modifier substituting a builtin",
			source:   regoModule("f(x) := count(x)\n\ndeny contains msga if {\n\tpod := input[_]\n\tf([1]) with count as http.send\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a with modifier on a data document",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tdata.postureControlInputs.a == 1 with data.postureControlInputs as {\"a\": 1}\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "an unknown function",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n\tregistry.lookup(pod.spec.image)\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			hermetic: false,
		},
		{
			name:     "a rule that does not compile",
			source:   regoModule("deny contains msga if {\n\tpod := input[_]\n}"),
			hermetic: false,
		},
		{
			name:     "a hermetic Rego v0 rule",
			source:   "package armo_builtins\n\ndeny[msga] {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}",
			hermetic: true,
		},
		{
			name:     "a Rego v0 rule reading the current time",
			source:   "package armo_builtins\n\ndeny[msga] {\n\tpod := input[_]\n\ttime.now_ns() > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}",
			hermetic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.hermetic, regoSourceIsHermetic(tt.source))
		})
	}
}

// Every builtin OPA marks nondeterministic is rejected, whatever it is called.
func TestNondeterministicBuiltinsAreNotHermetic(t *testing.T) {
	var nondeterministic []string
	for _, builtin := range ast.DefaultBuiltins {
		if builtin.Nondeterministic {
			nondeterministic = append(nondeterministic, builtin.Name)
			assert.False(t, builtinIsHermetic(builtin), builtin.Name)
		}
	}
	require.NotEmpty(t, nondeterministic)
	assert.Contains(t, nondeterministic, "http.send")
	assert.Contains(t, nondeterministic, "time.now_ns")
}

func TestExternalStateBuiltinsAreRegisteredAndRejected(t *testing.T) {
	registerOPABuiltins()
	for name := range externalStateBuiltins {
		builtin, ok := ast.BuiltinMap[name]
		require.True(t, ok, "%s is not a registered builtin; the list has a typo or is stale", name)
		assert.False(t, builtinIsHermetic(builtin), name)
	}
}

func TestCustomBuiltinsAreRejectedUnlessAllowlisted(t *testing.T) {
	registerOPABuiltins()

	assert.False(t, builtinIsHermetic(&ast.Builtin{Name: "kubescape.future_registry_lookup"}),
		"a builtin outside OPA's standard set must be rejected until it is reviewed")
	assert.False(t, builtinIsHermetic(nil))

	standard := standardBuiltinNames()
	for _, builtin := range ast.Builtins {
		if _, isStandard := standard[builtin.Name]; isStandard {
			continue
		}
		_, allowed := hermeticCustomBuiltins[builtin.Name]
		assert.Equal(t, allowed, builtinIsHermetic(builtin), "custom builtin %s", builtin.Name)
	}
	for name := range hermeticCustomBuiltins {
		builtin, ok := ast.BuiltinMap[name]
		require.True(t, ok, "%s is not a registered builtin", name)
		assert.True(t, builtinIsHermetic(builtin), name)
	}
}

// Infix operators are indexed by their symbols in ast.BuiltinMap; they must be
// classified by their canonical names.
func TestInfixOperatorsAreHermetic(t *testing.T) {
	for _, symbol := range []string{"==", "!=", "<", "+", "in"} {
		builtin, ok := ast.BuiltinMap[symbol]
		require.True(t, ok, symbol)
		assert.True(t, builtinIsHermetic(builtin), symbol)
	}
}

// TestStandardBuiltinSnapshot fails when an OPA upgrade changes the set of
// standard builtins. Review every added builtin for clock, network,
// filesystem, environment or randomness dependencies; add those that have
// one but are not marked Nondeterministic to externalStateBuiltins; then
// update the snapshot.
func TestStandardBuiltinSnapshot(t *testing.T) {
	names := make([]string, 0, len(ast.DefaultBuiltins))
	for _, builtin := range ast.DefaultBuiltins {
		names = append(names, builtin.Name)
	}
	slices.Sort(names)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(names, "\n"))))

	assert.Equal(t, 206, len(names))
	assert.Equal(t, "d07ebb889aa5da8b05b9d0aa2bee74ff5ebdda0d802e96e9f8de51d5b30f11c5", digest)
}

func TestRuleCacheEligibleChecksResourceEnumerator(t *testing.T) {
	const rule = "deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"
	tests := []struct {
		name       string
		enumerator string
		want       bool
	}{
		{
			name:       "a per-object hermetic enumerator",
			enumerator: regoModule("deny contains msga if {\n\tpod := input[_]\n\tpod.kind == \"Pod\"\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			want:       true,
		},
		{
			name:       "an enumerator reading the current time",
			enumerator: regoModule("deny contains msga if {\n\tpod := input[_]\n\ttime.now_ns() > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			want:       false,
		},
		{
			name:       "an enumerator calling the API client",
			enumerator: regoModule("deny contains msga if {\n\tpod := input[_]\n\tdata.kubernetes.api.client.query_all(\"pods\").status_code == 200\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			want:       false,
		},
		{
			name:       "an enumerator that relates objects",
			enumerator: regoModule("deny contains msga if {\n\tpod := input[_]\n\tcount(input) > 1\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			want:       false,
		},
		{
			name:       "an enumerator reading status",
			enumerator: regoModule("deny contains msga if {\n\tpod := input[_]\n\tpod.status.phase == \"Running\"\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyRule := cacheEligibilityRule("rule", rule, "pods")
			policyRule.ResourceEnumerator = tt.enumerator
			control := &reporthandling.Control{ControlID: "C-ENUM", Rules: []reporthandling.PolicyRule{policyRule}}
			assert.Equal(t, tt.want, ruleCacheEligible(control, &control.Rules[0]))
		})
	}
}

// The analysis is only reached through the incremental cache: a scan without
// it must not compile or analyse anything for eligibility.
func TestHermeticityAnalysisDoesNotRunWithoutIncrementalCache(t *testing.T) {
	source := regoModule("# analysis must not run without the cache\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}")
	scenario := newCacheScenario(t, regoControl("C-NOCACHE", "no-cache", source, "Pod"))
	scenario.put("/v1/pods", podObject("prod", "a", map[string]any{"hostPID": true}))

	full := scenario.evaluate(nil)
	require.Equal(t, "failed", full["/v1/prod/Pod/a"].Status)

	_, analysed := hermeticSources.Load(source)
	assert.False(t, analysed)
}

func TestRegoSourceIsHermeticIsSafeForConcurrentUse(t *testing.T) {
	sources := []string{
		regoModule("# concurrent 1\ndeny contains msga if {\n\tpod := input[_]\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
		regoModule("# concurrent 2\ndeny contains msga if {\n\tpod := input[_]\n\ttime.now_ns() > 0\n\tmsga := {\"alertObject\": {\"k8sApiObjects\": [pod]}}\n}"),
	}
	var wg sync.WaitGroup
	results := make([][]bool, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, source := range sources {
				results[i] = append(results[i], regoSourceIsHermetic(source))
			}
		}(i)
	}
	wg.Wait()
	for _, got := range results {
		assert.Equal(t, []bool{true, false}, got)
	}
}

// compileWithRuleDependencies is the single place evaluation and analysis
// compile through; it keeps the v1-then-v0 behaviour of getCompiledRule.
func TestCompileWithRuleDependencies(t *testing.T) {
	v1, version, err := compileWithRuleDependencies(context.Background(), "m", regoModule("deny contains 1 if true"), false)
	require.NoError(t, err)
	assert.Equal(t, ast.RegoV1, version)
	assert.Contains(t, v1.Modules, "cautils", "rule dependencies are compiled with the rule")

	_, version, err = compileWithRuleDependencies(context.Background(), "m", "package armo_builtins\n\ndeny[1] { true }", false)
	require.NoError(t, err)
	assert.Equal(t, ast.RegoV0, version)

	_, _, err = compileWithRuleDependencies(context.Background(), "m", "package armo_builtins\n\ndeny contains msga if {", false)
	assert.ErrorContains(t, err, "failed to compile rule 'm'")
}
