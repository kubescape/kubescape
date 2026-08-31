package cel

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

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

// TestListPoliciesCoversBundle checks the enumeration against the real embedded
// bundle: every policy the name-keyed lookups can reach must be listed, so a
// user reading the list is not offered a subset of what is deployable.
func TestListPoliciesCoversBundle(t *testing.T) {
	policies, err := ListPolicies()
	require.NoError(t, err)

	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	names := make(map[string]bool, len(policies))
	controls := make(map[string]bool, len(policies))
	for _, policy := range policies {
		assert.NotEmpty(t, policy.PolicyName)
		names[policy.PolicyName] = true
		if policy.ControlID != "" {
			controls[policy.ControlID] = true
		}
	}

	for name := range catalog.byName {
		assert.True(t, names[name], "policy %q missing from ListPolicies", name)
	}
	for controlID := range catalog.byControl {
		assert.True(t, controls[controlID], "control %q missing from ListPolicies", controlID)
	}
	for name := range catalog.dupNames {
		assert.True(t, names[name], "duplicated name %q missing from ListPolicies", name)
	}
}

// TestListPoliciesIsSortedByName pins the ordering callers render without
// sorting again.
func TestListPoliciesIsSortedByName(t *testing.T) {
	policies, err := ListPolicies()
	require.NoError(t, err)
	require.NotEmpty(t, policies)

	for i := 1; i < len(policies); i++ {
		assert.LessOrEqual(t, policies[i-1].PolicyName, policies[i].PolicyName)
	}
}

// TestListPoliciesAgreesWithControlLookup guards the listing against drifting
// from the lookup helpers: a control ID shown in the list must resolve to the
// same policy create-policy-binding would pick.
func TestListPoliciesAgreesWithControlLookup(t *testing.T) {
	policies, err := ListPolicies()
	require.NoError(t, err)

	withControl := 0
	for _, policy := range policies {
		if policy.ControlID == "" || policy.DuplicateControl {
			continue
		}
		withControl++

		name, err := PolicyNameForControl(policy.ControlID)
		require.NoError(t, err, "control %s is listed but does not resolve", policy.ControlID)
		assert.Equal(t, policy.PolicyName, name)

		paramKind, err := ParamKindForControl(policy.ControlID)
		require.NoError(t, err)
		assert.Equal(t, paramKind != nil, policy.TakesParams, "control %s params mismatch", policy.ControlID)
	}
	assert.NotZero(t, withControl, "the bundle must expose control-backed policies")
}

// TestListPoliciesReportsHelperPolicies checks the cluster-scoped helpers that
// carry no controlId are listed with an empty ControlID rather than dropped.
func TestListPoliciesReportsHelperPolicies(t *testing.T) {
	policies, err := ListPolicies()
	require.NoError(t, err)

	helpers := 0
	for _, policy := range policies {
		if policy.ControlID == "" {
			helpers++
		}
	}
	assert.NotZero(t, helpers, "the bundle carries cluster-scoped helper policies")
}

func TestListPoliciesMarksDuplicates(t *testing.T) {
	catalog, err := parseVAPBundle([]byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
  labels:
    controlId: C-0001
spec:
  validations:
    - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-b
  labels:
    controlId: C-0001
spec:
  validations:
    - expression: "true"
`))
	require.NoError(t, err)
	require.Contains(t, catalog.dupControls, "C-0001")
	require.Len(t, catalog.byName, 2)

	policies := listPolicies(catalog)
	require.Len(t, policies, 2)
	for _, policy := range policies {
		assert.True(t, policy.DuplicateControl, "policy %q shares control C-0001 and must be flagged", policy.PolicyName)
	}
}

func TestMatchedResourcesDeduplicatesAndSorts(t *testing.T) {
	resources := matchedResources(&admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			{RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{Resources: []string{"pods", "deployments"}}}},
			{RuleWithOperations: admissionregistrationv1.RuleWithOperations{Rule: admissionregistrationv1.Rule{Resources: []string{"pods", "cronjobs"}}}},
		},
	})
	assert.Equal(t, []string{"cronjobs", "deployments", "pods"}, resources)

	assert.Nil(t, matchedResources(nil))
}

// TestListPoliciesSurfacesDuplicateNames guards against a policy vanishing from
// the listing: a name claimed twice is dropped from the catalog index, and a
// discovery command that omitted it would report the bundle as smaller than it
// is.
func TestListPoliciesSurfacesDuplicateNames(t *testing.T) {
	catalog, err := parseVAPBundle([]byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
spec:
  validations:
    - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
spec:
  validations:
    - expression: "true"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-b
spec:
  validations:
    - expression: "true"
`))
	require.NoError(t, err)
	require.Contains(t, catalog.dupNames, "policy-a")
	require.NotContains(t, catalog.byName, "policy-a")

	policies := listPolicies(catalog)
	require.Len(t, policies, 2)

	byName := map[string]PolicyInfo{}
	for _, policy := range policies {
		byName[policy.PolicyName] = policy
	}
	require.Contains(t, byName, "policy-a")
	assert.True(t, byName["policy-a"].DuplicateName)
	assert.False(t, byName["policy-b"].DuplicateName)
}

// TestListPoliciesKeepsDistinctControlsOfADuplicateName covers the case where
// the two indexes disagree: the shared name is poisoned out of byName while
// each control ID stays individually resolvable through byControl. Listing only
// byName dropped both controls, so a control create-policy-binding accepts went
// missing from the command meant to discover it.
func TestListPoliciesKeepsDistinctControlsOfADuplicateName(t *testing.T) {
	catalog, err := parseVAPBundle([]byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
  labels:
    controlId: C-0001
spec:
  validations:
    - expression: "true"
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
	require.Empty(t, catalog.byName, "the shared name is poisoned out of byName")
	require.Len(t, catalog.byControl, 2)
	require.Empty(t, catalog.dupControls, "neither control ID is duplicated")

	policies := listPolicies(catalog)
	require.Len(t, policies, 2)

	controls := make([]string, 0, len(policies))
	for _, policy := range policies {
		controls = append(controls, policy.ControlID)
		assert.Equal(t, "policy-a", policy.PolicyName)
		assert.True(t, policy.DuplicateName, "--policy cannot resolve the shared name")
		assert.False(t, policy.DuplicateControl, "--control resolves each ID unambiguously")
	}
	assert.Equal(t, []string{"C-0001", "C-0002"}, controls)
}

// TestListPoliciesDoesNotDoubleReportADuplicateName checks the bare
// duplicate-name entry is only emitted when no control-backed copy already
// surfaced that name.
func TestListPoliciesDoesNotDoubleReportADuplicateName(t *testing.T) {
	catalog, err := parseVAPBundle([]byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: policy-a
  labels:
    controlId: C-0001
spec:
  validations:
    - expression: "true"
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

	blank := 0
	for _, policy := range listPolicies(catalog) {
		if policy.ControlID == "" {
			blank++
		}
	}
	assert.Zero(t, blank, "no placeholder entry once both controls are listed")
}
