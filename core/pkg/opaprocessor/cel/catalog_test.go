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
// policy loadVAP refuses: deploying/binding a namespaceSelector-narrowed policy
// is valid (live admission has the namespace labels the scan lacks), so metadata
// questions about it must not be blocked. Exercised via parseVAPBundle + lookup
// on an in-memory bundle, since the vendored bundle ships no such policy today.
func TestCatalogBypassesRequireSupported(t *testing.T) {
	bundle := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubescape-c-1001-gated
  labels:
    controlId: C-1001
spec:
  matchConstraints:
    namespaceSelector:
      matchLabels:
        env: prod
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["pods"]
  validations:
  - expression: "false"
`
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	vap := catalog.byControl["C-1001"]
	require.NotNil(t, vap)
	require.Error(t, vap.requireSupported(), "the offline eval path refuses the narrowed policy")

	// The name index still carries it, so name-keyed metadata stays answerable.
	named := catalog.byName["kubescape-c-1001-gated"]
	require.NotNil(t, named)
	assert.Equal(t, "C-1001", named.ControlID)
}

// TestMatchConstraintsForControl checks the constraints come off the embedded
// policy, since cmd/vap refuses a --resource-rule that falls outside them.
func TestMatchConstraintsForControl(t *testing.T) {
	constraints, err := MatchConstraintsForControl("C-0016")
	require.NoError(t, err)
	require.NotNil(t, constraints)

	var resources []string
	for _, rule := range constraints.ResourceRules {
		resources = append(resources, rule.Resources...)
	}
	assert.Contains(t, resources, "pods")
	assert.NotContains(t, resources, "sandboxes")

	_, err = MatchConstraintsForControl("C-9999")
	require.Error(t, err)
}

// TestMatchConstraintsForPolicyCopiesBundle proves callers get their own copy,
// so mutating the answer cannot poison the catalog every later lookup reads.
func TestMatchConstraintsForPolicyCopiesBundle(t *testing.T) {
	constraints, found, err := MatchConstraintsForPolicy("kubescape-c-0016-allow-privilege-escalation")
	require.NoError(t, err)
	require.True(t, found)
	require.NotEmpty(t, constraints.ResourceRules)

	constraints.ResourceRules[0].Resources = []string{"sandboxes"}

	fresh, _, err := MatchConstraintsForPolicy("kubescape-c-0016-allow-privilege-escalation")
	require.NoError(t, err)
	assert.NotEqual(t, []string{"sandboxes"}, fresh.ResourceRules[0].Resources)

	// A name outside the bundle reports found=false rather than erroring, so a
	// user-supplied policy name is left unchecked instead of blocked.
	_, found, err = MatchConstraintsForPolicy("some-custom-policy")
	require.NoError(t, err)
	assert.False(t, found)
}
