package cel

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
