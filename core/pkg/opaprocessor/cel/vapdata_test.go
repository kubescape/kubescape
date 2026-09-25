package cel

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// These tests guard the prerequisite the loader (loader.go) //go:embeds: the
// vendored bundle is actually in the tree and looks like the cel-admission-library
// release, so `make sync-vap` populated it and did not, say, leave an empty
// directory or an HTML error page. (vapdataDir is declared in loader.go.)

// TestVapdataBundlePresent checks the three files the engine relies on exist and
// are non-empty.
func TestVapdataBundlePresent(t *testing.T) {
	for _, name := range []string{
		"kubescape-validating-admission-policies.yaml",
		"basic-control-configuration.yaml",
		"policy-configuration-definition.yaml",
	} {
		info, err := os.Stat(filepath.Join(vapdataDir, name))
		require.NoErrorf(t, err, "%s must be vendored (run `make sync-vap`)", name)
		assert.NotZerof(t, info.Size(), "%s must not be empty", name)
	}
}

// TestVapdataHasValidatingAdmissionPolicies checks the policy file is the VAP
// bundle and carries a known control, so we did not vendor the wrong artifact.
func TestVapdataHasValidatingAdmissionPolicies(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vapdataDir, "kubescape-validating-admission-policies.yaml"))
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "kind: ValidatingAdmissionPolicy")
	assert.Contains(t, content, "controlId: C-0017")
}

// TestVapdataBasicControlConfiguration checks the params file is the control
// configuration the loader resolves paramKind values against.
func TestVapdataBasicControlConfiguration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vapdataDir, "basic-control-configuration.yaml"))
	require.NoError(t, err)

	content := string(data)
	assert.True(t, strings.Contains(content, "kind: ControlConfiguration"), "expected a ControlConfiguration document")
	assert.Contains(t, content, "settings:")
}

// paramsSettingsRef matches a `params.settings.<key>` read in a CEL expression.
// The bundle only ever uses the dot form today, but the index form is legal CEL
// for the same lookup, so both are matched rather than trusting a convention
// nothing enforces.
var paramsSettingsRef = regexp.MustCompile(`params\.settings(?:\.(\w+)|\[['"]([^'"]+)['"]\])`)

// knownMissingSettings are params.settings keys a bundle policy reads that the
// shipped basic-control-configuration.yaml does not define. An entry here is a
// live bug being tracked, not an accepted state, so each one carries the
// consequence rather than a bare key name.
//
// Both files are vendored from cel-admission-library by `make sync-vap`, so
// neither can be fixed in this repo: the fix ships in the library's own
// basic-control-configuration.yaml and arrives here at the next pin bump, at
// which point the entry below must be deleted and this test will say so.
// Empty is the good state: every key a bundle policy reads is shipped. The last
// entry here was cloudProvider, read by C-0020, which the library began shipping
// in basic-control-configuration.yaml and which arrived with a pin bump.
var knownMissingSettings = map[string]string{}

// TestBundleParamsSettingsAreShipped asserts every params.settings key a bundle
// policy reads is defined in the shipped control configuration.
//
// A missing key is not a loud failure at runtime. The policy resolves params,
// the lookup errors mid-expression, and the object lands in skipped, so the
// control silently reports nothing on precisely the resources it exists to
// catch. That is indistinguishable from "no violations found" in a scan result.
//
// This is cheapest to catch at a pin bump, when both files move together and
// the diff is in front of you, which is why it lives beside the other vendored
// bundle guards.
func TestBundleParamsSettingsAreShipped(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	// Where each key is read, so a failure names the policy to look at rather
	// than just the key.
	readBy := map[string][]string{}
	for name, vap := range catalog.byName {
		var expressions []string
		for _, v := range vap.Variables {
			expressions = append(expressions, v.Expression)
		}
		for _, v := range vap.Validations {
			expressions = append(expressions, v.Expression, v.MessageExpression)
		}
		for _, expression := range expressions {
			for _, m := range paramsSettingsRef.FindAllStringSubmatch(expression, -1) {
				key := m[1]
				if key == "" {
					key = m[2]
				}
				if !slices.Contains(readBy[key], name) {
					readBy[key] = append(readBy[key], name)
				}
			}
		}
	}
	require.NotEmpty(t, readBy, "no params.settings reads found in the bundle; the extraction is broken, not the bundle")

	data, err := os.ReadFile(filepath.Join(vapdataDir, "basic-control-configuration.yaml"))
	require.NoError(t, err)
	var config struct {
		Settings map[string]any `json:"settings"`
	}
	require.NoError(t, yaml.Unmarshal(data, &config))
	require.NotEmpty(t, config.Settings, "shipped control configuration has no settings block")

	for key, policies := range readBy {
		slices.Sort(policies)
		_, shipped := config.Settings[key]
		if reason, known := knownMissingSettings[key]; known {
			assert.Falsef(t, shipped,
				"params.settings.%s is now shipped in basic-control-configuration.yaml; "+
					"delete its knownMissingSettings entry, the bug it tracks is fixed", key)
			t.Logf("known gap: params.settings.%s, read by %s: %s", key, strings.Join(policies, ", "), reason)
			continue
		}
		assert.Truef(t, shipped,
			"policy %s reads params.settings.%s but the shipped basic-control-configuration.yaml does not define it. "+
				"The lookup errors mid-expression and the object is skipped, so the control silently reports nothing "+
				"on the resources it should flag. Fix it in cel-admission-library's basic-control-configuration.yaml, "+
				"or add it to knownMissingSettings with the consequence spelled out if it is a gap being tracked.",
			strings.Join(policies, ", "), key)
	}

	for key := range knownMissingSettings {
		assert.Containsf(t, readBy, key,
			"knownMissingSettings lists params.settings.%s but no bundle policy reads it any more; remove the entry", key)
	}
}

// knownUnresolvableParamKinds names the bundle policies whose paramKind the
// offline engine refuses, with what the refusal costs. Offline there is no
// binding, so only the shipped ControlConfiguration can answer a params.* read.
// Empty is the good state: every params-bearing bundle policy takes the
// ControlConfiguration the bundle ships, so none of them is silently skipped.
var knownUnresolvableParamKinds = map[string]string{}

// TestBundleParamKindsAreResolvable asserts every params-bearing policy in the
// bundle takes the ControlConfiguration the bundle ships, so requireSupported
// can honor it offline. A sync introducing another paramKind fails here rather
// than silently turning that control into a skip.
func TestBundleParamKindsAreResolvable(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	shipped, err := controlConfigParamKind()
	require.NoError(t, err)

	refused := map[string]bool{}
	for name, vap := range catalog.byName {
		if vap.paramKind == nil || *vap.paramKind == *shipped {
			continue
		}
		refused[vap.ControlID] = true
		reason, known := knownUnresolvableParamKinds[vap.ControlID]
		assert.Truef(t, known,
			"policy %s (control %q) takes params of kind %s %s, which the scan has no binding to resolve, so "+
				"requireSupported refuses it and the control is skipped on every object it matches. Point its "+
				"paramKind at the shipped %s %s, or add it to knownUnresolvableParamKinds with the consequence spelled out.",
			name, vap.ControlID, vap.paramKind.APIVersion, vap.paramKind.Kind, shipped.APIVersion, shipped.Kind)
		if known {
			t.Logf("known gap: control %s, %s", vap.ControlID, reason)
		}
	}

	for id := range knownUnresolvableParamKinds {
		assert.Containsf(t, refused, id,
			"knownUnresolvableParamKinds lists control %s but its paramKind now resolves (or it left the bundle); remove the entry", id)
	}
}

// makefilePath is the repo Makefile, relative to this package directory (the
// tests run from there, same as vapdataDir).
const makefilePath = "../../../../Makefile"

// celVapDigestsVar is the Makefile variable holding one name=sha256 pair per
// vendored asset.
const celVapDigestsVar = "CEL_VAP_DIGESTS"

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pinnedDigests parses the CEL_VAP_DIGESTS block out of the Makefile. The block
// is a backslash-continued list, so parsing follows the continuations rather
// than assuming a fixed number of lines.
func pinnedDigests(t *testing.T) map[string]string {
	t.Helper()

	data, err := os.ReadFile(makefilePath)
	require.NoError(t, err, "the Makefile must be readable from the package directory")

	lines := strings.Split(string(data), "\n")
	start := slices.IndexFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, celVapDigestsVar)
	})
	require.GreaterOrEqual(t, start, 0, "the Makefile must define %s", celVapDigestsVar)

	digests := map[string]string{}
	for i := start; i < len(lines); i++ {
		line := lines[i]
		// The declaration line carries the assignment; drop it so only the
		// name=digest pairs are parsed.
		if i == start {
			_, line, _ = strings.Cut(line, ":=")
		}
		line = strings.TrimSpace(line)
		more := strings.HasSuffix(line, `\`)
		line = strings.TrimSpace(strings.TrimSuffix(line, `\`))

		if name, digest, ok := strings.Cut(line, "="); ok {
			require.Truef(t, sha256Hex.MatchString(digest),
				"%s pins %s to %q, which is not a SHA256 digest", celVapDigestsVar, name, digest)
			// Rejected rather than overwritten: keeping the last pin would leave
			// the earlier one unchecked here while sync-vap, which walks every
			// pair, still fails on it. A duplicate is most likely two version
			// bumps merged together, which is one of the cases this guard exists
			// to catch.
			require.NotContainsf(t, digests, name, "%s pins %s more than once", celVapDigestsVar, name)
			digests[name] = digest
		}
		if !more {
			break
		}
	}

	require.NotEmpty(t, digests, "%s must pin at least one file", celVapDigestsVar)
	return digests
}

// TestVapdataMatchesPinnedDigests checks the bundle baked into the binary is the
// release the Makefile pins.
//
// sync-vap verifies what it DOWNLOADS, which leaves the vendored copy itself
// unguarded: a hand-edited policy, a bad merge, or a CEL_LIBRARY_VERSION bump
// whose digests were pasted without running `make sync-vap` all produce a tree
// where the pin and the embedded bundle disagree, and every other test still
// passes. Since the engine enforces these policies as a security scanner, an
// unnoticed edit to them is exactly the thing the digests exist to prevent.
//
// The hashes come from the embedded FS rather than from disk because that is
// what actually ships.
func TestVapdataMatchesPinnedDigests(t *testing.T) {
	pinned := pinnedDigests(t)

	entries, err := vapdataFS.ReadDir(vapdataDir)
	require.NoError(t, err, "the vendored bundle must be embedded")

	// README.md is vendored alongside the assets and is ours, not the release's,
	// so only the YAML the loader reads is pinned.
	embedded := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		content, err := vapdataFS.ReadFile(path.Join(vapdataDir, entry.Name()))
		require.NoError(t, err)
		embedded[entry.Name()] = fmt.Sprintf("%x", sha256.Sum256(content))
	}

	require.Equal(t, sortedNames(pinned), sortedNames(embedded),
		"%s and the vendored vapdata/*.yaml must cover the same files: a new release asset needs a digest, "+
			"and a dropped one needs its digest removed", celVapDigestsVar)

	for name, want := range pinned {
		assert.Equalf(t, want, embedded[name],
			"%s/%s does not match the SHA256 pinned in the Makefile. Either the vendored copy was edited by hand, "+
				"or %s was bumped without running `make sync-vap`", vapdataDir, name, celVapDigestsVar)
	}
}

// sortedNames returns a map's keys in a stable order, so a set mismatch
// reports as a readable diff of file names.
func sortedNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// runtimeReachableVAPs returns every policy loadVAP can reach, deduplicated by
// policy.
//
// byName and byControl are poisoned independently (see catalog.go): a name
// claimed by two policies is dropped from byName, while each of their distinct
// control IDs stays resolvable through byControl, which is the index loadVAP
// uses. Walking byName alone would let exactly those policies read
// namespaceObject unguarded.
func runtimeReachableVAPs(catalog *vapCatalog) []*VAP {
	seen := make(map[*VAP]struct{}, len(catalog.byName)+len(catalog.byControl))
	out := make([]*VAP, 0, len(seen))
	for _, index := range []map[string]*VAP{catalog.byName, catalog.byControl} {
		for _, vap := range index {
			if _, done := seen[vap]; done {
				continue
			}
			seen[vap] = struct{}{}
			out = append(out, vap)
		}
	}
	return out
}

// bundleExpression is one CEL expression from a policy, with where it came from
// so a failure names the field rather than just the policy.
type bundleExpression struct {
	source string
	where  string
}

// bundleExpressions returns every CEL expression a policy evaluates. All of them
// compile against the same env, so any of them can read namespaceObject.
func bundleExpressions(vap *VAP) []bundleExpression {
	var out []bundleExpression
	for _, v := range vap.Variables {
		out = append(out, bundleExpression{v.Expression, "variable " + v.Name})
	}
	for i, v := range vap.Validations {
		out = append(out, bundleExpression{v.Expression, "validation " + strconv.Itoa(i)})
		if v.MessageExpression != "" {
			out = append(out, bundleExpression{v.MessageExpression, "messageExpression " + strconv.Itoa(i)})
		}
	}
	for _, c := range vap.matchConditions {
		out = append(out, bundleExpression{c.Expression, "matchCondition " + c.Name})
	}
	return out
}

// TestReadsNamespaceObjectScoping covers the two ways a plain name comparison
// gets the answer wrong: a comprehension local that never touches the
// activation, and a real global read that shadowing rewrites to its absolute
// name.
func TestReadsNamespaceObjectScoping(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		expr  string
		reads bool
	}{
		{"plain global read", "namespaceObject.metadata.name == 'x'", true},
		{"shadowed global kept as an absolute name", "[true].all(namespaceObject, .namespaceObject.metadata.name == 'allowed')", true},
		{"comprehension local of the same name", "[true].all(namespaceObject, namespaceObject)", false},
		{"an iteration range is the outer scope", "namespaceObject.metadata.labels.all(namespaceObject, namespaceObject != '')", true},
		{"a mention inside a string", "'see the namespaceObject docs'", false},
		{"unrelated expression", "has(object.spec)", false},
		{"does not compile", "namespaceObject.(((", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.reads, readsNamespaceObject(e.env, tc.expr))
		})
	}
}

func TestPolicyDetectsNamespaceObjectOnlyWhenValidationCanReachIt(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		vap  *VAP
		want bool
	}{
		{"validation reads namespace", &VAP{Validations: []Validation{{Expression: "namespaceObject.metadata.name == 'prod'"}}}, true},
		{"validation reaches variable", &VAP{Variables: []Variable{{Name: "namespace", Expression: "namespaceObject.metadata.name"}}, Validations: []Validation{{Expression: "variables.namespace == 'prod'"}}}, true},
		{"validation reaches nested variable", &VAP{Variables: []Variable{{Name: "namespace", Expression: "namespaceObject.metadata.name"}, {Name: "allowed", Expression: "variables.namespace == 'prod'"}}, Validations: []Validation{{Expression: "variables.allowed"}}}, true},
		{"absolute global variable inside a shadowing comprehension", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "[true].all(variables, .variables.allowed)"}}}, true},
		{"comprehension-local variable does not reach global declaration", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "[{'allowed': false}].all(variables, variables.allowed)"}}}, false},
		{"literal-key variable access reaches global declaration", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "variables['allowed']"}}}, true},
		{"absolute literal-key variable access inside a shadowing comprehension", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "[true].all(variables, .variables['allowed'])"}}}, true},
		{"literal-key comprehension-local variable does not reach global declaration", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "[{'allowed': false}].all(variables, variables['allowed'])"}}}, false},
		{"dynamic key can reach namespace-dependent variable", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "dyn(variables)[object.metadata.name]"}}}, true},
		{"dynamic key through a referenced variable can reach namespace-dependent variable", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}, {Name: "selected", Expression: "dyn(variables)[object.metadata.name]"}}, Validations: []Validation{{Expression: "variables.selected"}}}, true},
		{"dynamic comprehension-local variable does not reach global declaration", &VAP{Variables: []Variable{{Name: "allowed", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "[{'allowed': false}].all(variables, dyn(variables)[object.metadata.name])"}}}, false},
		{"unused lazy variable", &VAP{Variables: []Variable{{Name: "namespace", Expression: "namespaceObject.metadata.name"}}, Validations: []Validation{{Expression: "object.metadata.name == 'pod'"}}}, false},
		{"message expression", &VAP{Validations: []Validation{{Expression: "true", MessageExpression: "namespaceObject.metadata.name"}}}, false},
		{"match condition", &VAP{matchConditions: []MatchCondition{{Name: "gate", Expression: "namespaceObject.metadata.name == 'prod'"}}, Validations: []Validation{{Expression: "true"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, e.ReadsNamespaceObjectInValidations(tc.vap))
		})
	}
}

// TestBundleGuardCoversDuplicateNamePolicies covers the catalog shape where the
// two indexes disagree. A name claimed twice is poisoned out of byName, but each
// distinct control ID stays resolvable through byControl, which is what loadVAP
// uses, so a guard walking byName alone would see nothing at all here.
func TestBundleGuardCoversDuplicateNamePolicies(t *testing.T) {
	catalog, err := parseVAPBundle([]byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
  labels:
    controlId: C-0001
spec:
  validations:
    - expression: "namespaceObject.metadata.name == 'allowed'"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
  labels:
    controlId: C-0002
spec:
  validations:
    - expression: "true"
`))
	require.NoError(t, err)
	require.Empty(t, catalog.byName, "a name claimed twice is poisoned out of byName")
	require.Len(t, catalog.byControl, 2, "each control ID stays resolvable")

	vaps := runtimeReachableVAPs(catalog)
	require.Len(t, vaps, 2, "both policies are still reachable through loadVAP")

	e, err := NewEvaluator()
	require.NoError(t, err)

	var found []string
	for _, vap := range vaps {
		for _, expr := range bundleExpressions(vap) {
			if readsNamespaceObject(e.env, expr.source) {
				found = append(found, vap.ControlID)
			}
		}
	}
	assert.Equal(t, []string{"C-0001"}, found,
		"a read reachable only through byControl must still be caught")
}
