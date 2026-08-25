package cel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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

// TestVAPFailurePolicy pins how spec.failurePolicy is resolved: omitted defaults
// to Fail (the apiserver's default), an explicit Fail stays Fail, and only
// Ignore flips failOnError to false.
func TestVAPFailurePolicy(t *testing.T) {
	doc := func(failurePolicy string) string {
		return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: pol
  labels:
    controlId: C-1000
spec:
` + failurePolicy + `  validations:
  - expression: "true"
`
	}

	tests := []struct {
		name          string
		failurePolicy string
		wantFail      bool
	}{
		{name: "omitted defaults to Fail", failurePolicy: "", wantFail: true},
		{name: "explicit Fail", failurePolicy: "  failurePolicy: Fail\n", wantFail: true},
		{name: "explicit Ignore", failurePolicy: "  failurePolicy: Ignore\n", wantFail: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := parseVAPBundle([]byte(doc(tt.failurePolicy)))
			require.NoError(t, err)
			vap, ok := catalog.byControl["C-1000"]
			require.True(t, ok)
			assert.Equal(t, tt.wantFail, vap.failOnError())
		})
	}
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
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)
	assert.Len(t, catalog.byControl, 1)
	assert.Contains(t, catalog.byControl, "C-1000")
}

// TestParseVAPBundleSkipsNoControlID proves policies without a controlId label
// (cluster-scoped helpers) stay out of the control index (no empty key) while
// remaining reachable by name, since name-keyed callers still need them.
func TestParseVAPBundleSkipsNoControlID(t *testing.T) {
	bundle := vapDoc("cluster-policy-helper", "") + "---\n" + vapDoc("kubescape-c-1000", "C-1000")
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)
	assert.Len(t, catalog.byControl, 1)
	assert.Contains(t, catalog.byControl, "C-1000")
	assert.NotContains(t, catalog.byControl, "")
	assert.Contains(t, catalog.byName, "cluster-policy-helper")
}

// TestParseVAPBundleDuplicateControl proves a duplicated control poisons only
// itself: neither copy silently wins (it is dropped from the index and returned
// in the duplicates set), while the rest of the bundle still indexes. One bad
// control must not take the whole engine offline.
func TestParseVAPBundleDuplicateControl(t *testing.T) {
	bundle := vapDoc("kubescape-c-1000-a", "C-1000") +
		"---\n" + vapDoc("kubescape-c-1000-b", "C-1000") +
		"---\n" + vapDoc("kubescape-c-2000", "C-2000")
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	assert.NotContains(t, catalog.byControl, "C-1000", "a duplicated control must not silently win")
	assert.Contains(t, catalog.dupControls, "C-1000")
	assert.Contains(t, catalog.byControl, "C-2000", "an unrelated control must still index")
}

// TestParseVAPBundleDuplicateName proves the same poisoning applies to the name
// index: two policies sharing a metadata.name is a bundle bug (the bundle could
// not even be kubectl-applied), so neither wins and name lookups refuse it,
// while other names still index.
func TestParseVAPBundleDuplicateName(t *testing.T) {
	bundle := vapDoc("kubescape-c-1000", "C-1000") +
		"---\n" + vapDoc("kubescape-c-1000", "C-1001") +
		"---\n" + vapDoc("kubescape-c-2000", "C-2000")
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	assert.NotContains(t, catalog.byName, "kubescape-c-1000", "a duplicated name must not silently win")
	assert.Contains(t, catalog.dupNames, "kubescape-c-1000")
	assert.Contains(t, catalog.byName, "kubescape-c-2000", "an unrelated name must still index")
}

// TestLoadVAPAcceptsMatchConditions proves a policy with a matchConditions gate
// loads with its conditions captured, rather than being refused. The evaluator
// honors the gate per object (see TestMatchConditions*), so refusing the control
// outright would drop it from the scan for no reason.
func TestLoadVAPAcceptsMatchConditions(t *testing.T) {
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
	catalog, err := parseVAPBundle([]byte(bundle))
	require.NoError(t, err)

	vap := catalog.byControl["C-1001"]
	require.NotNil(t, vap)
	require.Len(t, vap.matchConditions, 1, "matchConditions must be captured, not dropped")
	assert.Equal(t, "only-kube-system", vap.matchConditions[0].Name)
	assert.Equal(t, "object.metadata.namespace == 'kube-system'", vap.matchConditions[0].Expression)

	assert.NoError(t, vap.requireSupported(), "a gated policy is evaluated, not refused")
}

// TestLoadVAPRefusesNarrowingSelectors pins which selector is refused and which
// is not. namespaceSelector reads the NAMESPACE's labels, which the scan only
// has when some control's match happened to collect Namespaces, so a policy
// narrowing with it is refused (a loud skip) rather than evaluated against an
// input that may be absent (a silent parity break). objectSelector reads the
// scanned object's own labels, which the scan always has, so it is evaluated in
// appliesTo instead of refused — see TestVAPAppliesToObjectSelector. An empty
// selector matches everything (it is what the apiserver defaults an omitted one
// to), so it must not trip the refusal either.
func TestLoadVAPRefusesNarrowingSelectors(t *testing.T) {
	policy := func(selectorYAML string) string {
		return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubescape-c-1002
  labels:
    controlId: C-1002
spec:
  matchConstraints:
` + selectorYAML + `    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["pods"]
  validations:
  - expression: "false"
`
	}

	cases := []struct {
		name         string
		selectorYAML string
		refusedFor   string // empty: must be supported
	}{
		{
			name: "namespaceSelector with labels is refused",
			selectorYAML: `    namespaceSelector:
      matchLabels:
        env: prod
`,
			refusedFor: "namespaceSelector",
		},
		{
			name: "objectSelector with expressions is supported, not refused",
			selectorYAML: `    objectSelector:
      matchExpressions:
      - key: app
        operator: Exists
`,
			refusedFor: "",
		},
		{
			name: "empty selectors match everything and are supported",
			selectorYAML: `    namespaceSelector: {}
    objectSelector: {}
`,
			refusedFor: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog, err := parseVAPBundle([]byte(policy(tc.selectorYAML)))
			require.NoError(t, err)
			vap := catalog.byControl["C-1002"]
			require.NotNil(t, vap)

			err = vap.requireSupported()
			if tc.refusedFor == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.refusedFor)
		})
	}
}

// TestLoadVAPRefusesForeignParamKind pins the paramKind refusal. Only the
// ControlConfiguration the bundle ships can be resolved offline; any other kind
// would come from a binding's ParamRef the scan does not have, so it is refused
// (a loud skip) rather than evaluated against whatever params.* happens to be
// bound.
func TestLoadVAPRefusesForeignParamKind(t *testing.T) {
	policy := func(paramKindYAML string) string {
		return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kubescape-c-1003
  labels:
    controlId: C-1003
spec:
` + paramKindYAML + `  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["pods"]
  validations:
  - expression: "false"
`
	}

	cases := []struct {
		name          string
		paramKindYAML string
		refused       bool
	}{
		{
			name:          "no paramKind is supported",
			paramKindYAML: "",
		},
		{
			name: "the bundled ControlConfiguration is supported",
			paramKindYAML: `  paramKind:
    apiVersion: kubescape.io/v1
    kind: ControlConfiguration
`,
		},
		{
			name: "another kind in the bundled group is refused",
			paramKindYAML: `  paramKind:
    apiVersion: kubescape.io/v1
    kind: ScanConfiguration
`,
			refused: true,
		},
		{
			name: "another version of the bundled kind is refused",
			paramKindYAML: `  paramKind:
    apiVersion: kubescape.io/v2
    kind: ControlConfiguration
`,
			refused: true,
		},
		{
			name: "a cluster CRD kind is refused",
			paramKindYAML: `  paramKind:
    apiVersion: ate.dev/v1alpha1
    kind: WorkerPool
`,
			refused: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog, err := parseVAPBundle([]byte(policy(tc.paramKindYAML)))
			require.NoError(t, err)
			vap := catalog.byControl["C-1003"]
			require.NotNil(t, vap)

			err = vap.requireSupported()
			if !tc.refused {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err, "a paramKind the bundle cannot supply must be refused")
			assert.Contains(t, err.Error(), "C-1003")
			assert.Contains(t, err.Error(), vap.paramKind.Kind)
		})
	}
}

// TestResolveParamsRefusesForeignParamKind covers the same invariant where the
// params are actually bound: a foreign paramKind must not silently receive the
// ControlConfiguration, whose fields belong to another kind entirely.
func TestResolveParamsRefusesForeignParamKind(t *testing.T) {
	vap := &VAP{
		ControlID: "C-1004",
		paramKind: &admissionregistrationv1.ParamKind{APIVersion: "ate.dev/v1alpha1", Kind: "WorkerPool"},
	}

	params, err := resolveParams(vap)
	require.Error(t, err, "resolveParams must not fall back to the ControlConfiguration")
	assert.Nil(t, params)
	assert.Contains(t, err.Error(), "WorkerPool")
}

// TestControlConfigParamKindMatchesShippedFile keeps the check honest against
// the file it reads: the GVK comes off basic-control-configuration.yaml, so a
// `make sync-vap` that renames or re-versions it moves the check with it rather
// than refusing every params-bearing control.
func TestControlConfigParamKindMatchesShippedFile(t *testing.T) {
	shipped, err := controlConfigParamKind()
	require.NoError(t, err)

	config, err := controlConfig()
	require.NoError(t, err)
	assert.Equal(t, config["apiVersion"], shipped.APIVersion)
	assert.Equal(t, config["kind"], shipped.Kind)

	vap, err := loadVAP("C-0046")
	require.NoError(t, err)
	assert.Equal(t, *shipped, *vap.paramKind, "the bundle's params-bearing controls must still resolve")
}

// TestResolveParamObjectFallback verifies a binding with no paramRef (or a
// policy with no paramKind) falls back to the bundled ControlConfiguration.
func TestResolveParamObjectFallback(t *testing.T) {
	vap, err := loadVAP("C-0046")
	require.NoError(t, err)

	// No paramRef falls back to the bundled config.
	params, err := ResolveParamObject(vap, nil, "default", nil)
	require.NoError(t, err)
	config, err := controlConfig()
	require.NoError(t, err)
	assert.Equal(t, config, params)

	// A paramless control is always nil.
	vapNoParam, err := loadVAP("C-0017")
	require.NoError(t, err)
	params, err = ResolveParamObject(vapNoParam, &admissionregistrationv1.ParamRef{Name: "x"}, "default", nil)
	require.NoError(t, err)
	assert.Nil(t, params)
}

// TestResolveParamObjectBinding resolves a binding's paramRef to a scanned
// object of the policy's paramKind kind.
func TestResolveParamObjectBinding(t *testing.T) {
	vap, err := loadVAP("C-0046")
	require.NoError(t, err)

	custom := map[string]any{
		"apiVersion": "kubescape.io/v1",
		"kind":       vap.paramKind.Kind,
		"metadata": map[string]any{
			"name":      "custom",
			"namespace": "default",
		},
		"settings": map[string]any{"insecureCapabilities": []any{"ADD"}},
	}
	findParam := func(apiVersion, kind, namespace, name string) (map[string]any, bool) {
		if apiVersion == vap.paramKind.APIVersion && kind == vap.paramKind.Kind && namespace == "default" && name == "custom" {
			return custom, true
		}
		return nil, false
	}

	ref := &admissionregistrationv1.ParamRef{
		Name:      "custom",
		Namespace: "default",
	}
	params, err := ResolveParamObject(vap, ref, "other", findParam)
	require.NoError(t, err)
	assert.Equal(t, custom, params)

	// Empty namespace in the paramRef uses the resource's namespace.
	ref.Namespace = ""
	params, err = ResolveParamObject(vap, ref, "default", findParam)
	require.NoError(t, err)
	assert.Equal(t, custom, params)

	// Missing object returns ErrParamNotFound.
	_, err = ResolveParamObject(vap, &admissionregistrationv1.ParamRef{Name: "missing"}, "default", findParam)
	require.ErrorIs(t, err, ErrParamNotFound)
}
