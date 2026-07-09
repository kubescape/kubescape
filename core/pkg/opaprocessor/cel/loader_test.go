package cel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadVAPParamlessControl loads a known paramless control and checks the
// structured pieces the evaluator needs come back intact.
func TestLoadVAPParamlessControl(t *testing.T) {
	vap, err := loadVAP("C-0017")
	require.NoError(t, err)

	assert.Equal(t, "C-0017", vap.ControlID)
	assert.Contains(t, vap.PolicyName, "c-0017")
	assert.Nil(t, vap.paramKind, "C-0017 declares no paramKind")

	// The C-0017 bundle policy has three validations (Pod, workload, CronJob).
	require.Len(t, vap.Validations, 3)
	assert.Contains(t, vap.Validations[0].Expression, "readOnlyRootFilesystem")
	assert.NotEmpty(t, vap.Validations[0].Message)

	// A paramless policy resolves to nil params, matching a live binding with no
	// ParamRef.
	params, err := resolveParams(vap)
	require.NoError(t, err)
	assert.Nil(t, params)
}

// TestLoadVAPWithParams loads a control that declares a paramKind and checks
// resolveParams pulls the real values out of basic-control-configuration.yaml.
func TestLoadVAPWithParams(t *testing.T) {
	vap, err := loadVAP("C-0046")
	require.NoError(t, err)

	require.NotNil(t, vap.paramKind, "C-0046 declares a paramKind")
	assert.Equal(t, "ControlConfiguration", vap.paramKind.Kind)

	// The validations reference params.settings.insecureCapabilities, so the
	// resolved params must expose that under settings.
	require.NotEmpty(t, vap.Validations)
	assert.Contains(t, vap.Validations[0].Expression, "params.settings.insecureCapabilities")

	params, err := resolveParams(vap)
	require.NoError(t, err)

	settings, ok := params.(map[string]any)["settings"].(map[string]any)
	require.True(t, ok, "resolved params must carry a settings map")

	caps, ok := settings["insecureCapabilities"].([]any)
	require.True(t, ok, "settings.insecureCapabilities must be a list")
	require.NotEmpty(t, caps)

	var haveSysAdmin bool
	for _, c := range caps {
		if c == "SYS_ADMIN" {
			haveSysAdmin = true
		}
	}
	assert.True(t, haveSysAdmin, "expected SYS_ADMIN among the vendored insecureCapabilities")
}

// TestLoadVAPUnknownControl asserts an unknown control fails loudly rather than
// returning an empty policy a scan would treat as "nothing to check".
func TestLoadVAPUnknownControl(t *testing.T) {
	_, err := loadVAP("C-9999")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "C-9999"))
}

// vapDoc renders a minimal VAP document for the in-memory bundle tests.
func vapDoc(name, controlID string) string {
	labels := ""
	if controlID != "" {
		labels = "\n  labels:\n    controlId: " + controlID
	}
	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ` + name + labels + `
spec:
  validations:
  - expression: "true"
`
}

// TestParseVAPBundleSkipsForeignKinds proves a non-VAP document (the bindings the
// upstream bundle commonly ships) is skipped, not fatal: the VAP alongside it
// still indexes. This is the guard against a routine `make sync-vap` taking the
// whole engine down.
func TestParseVAPBundleSkipsForeignKinds(t *testing.T) {
	bundle := vapDoc("kubescape-c-1000", "C-1000") + `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: kubescape-c-1000-binding
spec:
  policyName: kubescape-c-1000
`
	index, _, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)
	assert.Len(t, index, 1)
	assert.Contains(t, index, "C-1000")
}

// TestParseVAPBundleSkipsNoControlID proves policies without a controlId label
// (cluster-scoped helpers) are dropped from the index rather than indexed under
// an empty key.
func TestParseVAPBundleSkipsNoControlID(t *testing.T) {
	bundle := vapDoc("cluster-policy-helper", "") + "---\n" + vapDoc("kubescape-c-1000", "C-1000")
	index, _, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)
	assert.Len(t, index, 1)
	assert.Contains(t, index, "C-1000")
	assert.NotContains(t, index, "")
}

// TestParseVAPBundleDuplicateControl proves a duplicated control poisons only
// itself: neither copy silently wins (it is dropped from the index and returned
// in the duplicates set), while the rest of the bundle still indexes. One bad
// control must not take the whole engine offline.
func TestParseVAPBundleDuplicateControl(t *testing.T) {
	bundle := vapDoc("kubescape-c-1000-a", "C-1000") +
		"---\n" + vapDoc("kubescape-c-1000-b", "C-1000") +
		"---\n" + vapDoc("kubescape-c-2000", "C-2000")
	index, duplicates, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	assert.NotContains(t, index, "C-1000", "a duplicated control must not silently win")
	assert.Contains(t, duplicates, "C-1000")
	assert.Contains(t, index, "C-2000", "an unrelated control must still index")
}

// TestLoadVAPRefusesMatchConditions proves a policy with a matchConditions gate is
// captured but refused, rather than having its validations run unconditionally.
// Today's bundle ships none, but a future sync could, and running one offline
// would emit violations live admission (which honors the gate) never would.
func TestLoadVAPRefusesMatchConditions(t *testing.T) {
	bundle := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubescape-c-1001
  labels:
    controlId: C-1001
spec:
  matchConditions:
  - name: only-kube-system
    expression: "object.metadata.namespace == 'kube-system'"
  validations:
  - expression: "false"
`
	index, _, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	vap := index["C-1001"]
	require.NotNil(t, vap)
	require.NotEmpty(t, vap.matchConditions, "matchConditions must be captured, not dropped")

	err = vap.requireSupported()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matchConditions")
}
