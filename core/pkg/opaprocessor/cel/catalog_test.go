package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyNameForControl checks the control -> policy-name lookup against the
// real embedded bundle, so callers (cmd/vap) resolve exactly the names the
// deployable YAML carries.
func TestPolicyNameForControl(t *testing.T) {
	name, err := PolicyNameForControl("C-0016")
	require.NoError(t, err)
	assert.Equal(t, "kubescape-c-0016-allow-privilege-escalation", name)

	_, err = PolicyNameForControl("C-9999")
	require.Error(t, err, "a control absent from the bundle must fail loudly")
}

// TestParamKindForControl checks paramKind is read off the embedded policy.
// C-0009 is the regression case: the retired hand-typed params map did not list
// it, even though its policy declares a paramKind — the exact drift deriving
// from the YAML is meant to prevent.
func TestParamKindForControl(t *testing.T) {
	paramKind, err := ParamKindForControl("C-0009")
	require.NoError(t, err)
	require.NotNil(t, paramKind, "C-0009 declares a paramKind in the bundle")
	assert.Equal(t, "ControlConfiguration", paramKind.Kind)

	paramKind, err = ParamKindForControl("C-0016")
	require.NoError(t, err)
	assert.Nil(t, paramKind, "C-0016 declares no paramKind")

	_, err = ParamKindForControl("C-9999")
	require.Error(t, err)
}

// TestParamKindForPolicy checks the name-keyed lookup, including the policies a
// control lookup can never reach: cluster-scoped helpers with no controlId.
func TestParamKindForPolicy(t *testing.T) {
	// A cluster helper with params: no controlId label, so only reachable by name.
	paramKind, found, err := ParamKindForPolicy("cluster-policy-deny-insecure-capabilities")
	require.NoError(t, err)
	require.True(t, found)
	require.NotNil(t, paramKind)
	assert.Equal(t, "ControlConfiguration", paramKind.Kind)

	// A paramless control policy, by name.
	paramKind, found, err = ParamKindForPolicy("kubescape-c-0017-deny-resources-with-mutable-container-filesystem")
	require.NoError(t, err)
	require.True(t, found)
	assert.Nil(t, paramKind)

	// A name outside the bundle reports found=false, not an error: callers with
	// arbitrary user-supplied policy names skip paramKind checks then.
	_, found, err = ParamKindForPolicy("some-custom-policy")
	require.NoError(t, err)
	assert.False(t, found)
}

// TestCatalogBypassesRequireSupported proves the metadata helpers answer for a
// matchConditions-gated policy loadVAP refuses: deploying/binding such a policy
// is valid (live admission evaluates the gate), so metadata questions about it
// must not be blocked. Exercised via parseVAPBundle + lookup on an in-memory
// bundle, since the vendored bundle ships no gated policies today.
func TestCatalogBypassesRequireSupported(t *testing.T) {
	bundle := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubescape-c-1001-gated
  labels:
    controlId: C-1001
spec:
  matchConditions:
  - name: only-kube-system
    expression: "object.metadata.namespace == 'kube-system'"
  validations:
  - expression: "false"
`
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	vap := catalog.byControl["C-1001"]
	require.NotNil(t, vap)
	require.Error(t, vap.requireSupported(), "the offline eval path refuses the gated policy")

	// The name index still carries it, so name-keyed metadata stays answerable.
	named := catalog.byName["kubescape-c-1001-gated"]
	require.NotNil(t, named)
	assert.Equal(t, "C-1001", named.ControlID)
}
