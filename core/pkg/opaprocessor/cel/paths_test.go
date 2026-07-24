package cel

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func planFor(t *testing.T, expr string) pathPlan {
	t.Helper()
	e, err := NewEvaluator()
	require.NoError(t, err)
	return e.buildPathPlan(expr)
}

func TestPathPlanDirectFields(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []fieldRef
	}{
		{
			name: "equality against a literal carries the value to set",
			expr: "object.kind != 'Pod' || !has(object.spec.hostNetwork) || object.spec.hostNetwork == false",
			want: []fieldRef{{path: "spec.hostNetwork", value: "false"}},
		},
		{
			name: "presence test alone carries no value",
			expr: "object.kind != 'Pod' || has(object.metadata.ownerReferences)",
			want: []fieldRef{{path: "metadata.ownerReferences"}},
		},
		{
			name: "inequality states what the field must not be, which is not a value",
			expr: "object.kind != 'Pod' || object.metadata.namespace != 'default'",
			want: []fieldRef{{path: "metadata.namespace"}},
		},
		{
			name: "the presence test of a field read for equality is not a separate path",
			expr: "has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false",
			want: []fieldRef{{path: "spec.automountServiceAccountToken", value: "false"}},
		},
		{
			name: "several fields each keep their own value",
			expr: "(!has(object.spec.hostPID) || object.spec.hostPID == false) && (!has(object.spec.hostIPC) || object.spec.hostIPC == false)",
			want: []fieldRef{
				{path: "spec.hostIPC", value: "false"},
				{path: "spec.hostPID", value: "false"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planFor(t, tc.expr)
			assert.Equal(t, tc.want, plan.direct)
			assert.Nil(t, plan.elements)
		})
	}
}

func TestPathPlanSkipsScopeGuards(t *testing.T) {
	// Every policy in the bundle opens by testing object.kind, and one shape
	// tests it inside a comprehension over an inline list of kinds. Neither is
	// something a user fixes, and neither list is a list on the object.
	plan := planFor(t, "['Deployment','Job'].all(kind, object.kind != kind) || object.spec.template.spec.hostNetwork == false")
	assert.Equal(t, []fieldRef{{path: "spec.template.spec.hostNetwork", value: "false"}}, plan.direct)
	assert.Nil(t, plan.elements, "a comprehension over an inline list is not a list on the object")
}

func TestPathPlanElementFields(t *testing.T) {
	cases := []struct {
		name       string
		expr       string
		collection string
		want       []fieldRef
	}{
		{
			name:       "container field with the value it must hold",
			expr:       "object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem == true)",
			collection: "spec.containers",
			want:       []fieldRef{{path: "securityContext.readOnlyRootFilesystem", value: "true"}},
		},
		{
			name:       "nested presence tests collapse onto the fields actually required",
			expr:       "object.spec.containers.all(c, has(c.resources) && has(c.resources.limits) && has(c.resources.limits.memory) && has(c.resources.limits.cpu))",
			collection: "spec.containers",
			want: []fieldRef{
				{path: "resources.limits.cpu"},
				{path: "resources.limits.memory"},
			},
		},
		{
			name:       "a comprehension over params does not shadow the one over the object",
			expr:       "object.spec.containers.all(c, params.settings.registries.all(r, !c.image.startsWith(r)))",
			collection: "spec.containers",
			want:       []fieldRef{{path: "image"}},
		},
		{
			// A collection the element iterates in turn cannot be pinned to an
			// inner index, but it is still reported: it names the offending
			// element's field to look at, unlike the object-level list we index.
			name:       "a collection iterated inside the element stays a review path",
			expr:       "object.spec.containers.all(c, !has(c.ports) || c.ports.all(p, !has(p.hostPort)))",
			collection: "spec.containers",
			want:       []fieldRef{{path: "ports"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planFor(t, tc.expr)
			require.NotNil(t, plan.elements)
			assert.Equal(t, tc.collection, plan.elements.collection)
			assert.Equal(t, tc.want, plan.elements.fields)
			assert.Empty(t, plan.direct, "the iterated list is not a path of its own")
		})
	}
}

func TestPathPlanIgnoresElementsWhenTwoObjectListsAreIterated(t *testing.T) {
	// With two lists in play a failure cannot be attributed to either one, and
	// blaming the wrong list would put a wrong path in front of the user. Both
	// lists drop out rather than being reported as suspects.
	plan := planFor(t, "object.spec.volumes.all(v, !has(v.hostPath)) && object.spec.containers.all(c, has(c.readinessProbe))")
	assert.Nil(t, plan.elements)
	assert.Empty(t, plan.direct)
}

func TestPathPlanNoElementsForBareExists(t *testing.T) {
	// exists fails when NO element satisfies the predicate, so narrowing to one
	// element and re-checking would flag every element as the offender. There is
	// no sound way to attribute the failure, so no element is attributed.
	plan := planFor(t, "object.kind != 'Pod' || object.spec.containers.exists(c, c.name == 'sidecar')")
	assert.Nil(t, plan.elements, "a bare exists cannot pin a failing element")
	assert.Empty(t, plan.direct)
}

func TestPathPlanAttributesElementsForNegatedExists(t *testing.T) {
	// !exists(e, p) is all(e, !p): re-checking a single element is exact again,
	// so the element that satisfies p (the one causing the violation) can be
	// named. But the equality lives under the exists accumulator's disjunction,
	// so its literal is not a value to write.
	plan := planFor(t, "object.kind != 'Pod' || !object.spec.containers.exists(c, c.name == 'bad')")
	require.NotNil(t, plan.elements)
	assert.Equal(t, "spec.containers", plan.elements.collection)
	require.Len(t, plan.elements.fields, 1)
	assert.Equal(t, "name", plan.elements.fields[0].path)
	assert.Empty(t, plan.elements.fields[0].value, "an exists alternative is not a fix value")
}

func TestPathPlanDropsValueForDisjunctiveAlternatives(t *testing.T) {
	// The heart of the disjunction blocker: two independent object fields, either
	// of which satisfies the policy. Writing both as fixes would move the
	// workload into kube-system to satisfy a host-network policy, so neither
	// carries a value.
	plan := planFor(t, "object.metadata.namespace == 'kube-system' || object.spec.hostNetwork == false")
	require.Len(t, plan.direct, 2)
	for _, ref := range plan.direct {
		assert.Emptyf(t, ref.value, "%s is one of two alternatives, not a required value", ref.path)
	}
}

func TestPathPlanDropsElementValueUnderOuterDisjunction(t *testing.T) {
	// The element equality is conjunctive WITHIN the predicate, but the whole
	// comprehension is one branch of an outer disjunction whose other branch is
	// an independent object field. Setting the element value is then an
	// alternative to satisfying that other branch, not a requirement - and for a
	// field like name, writing it onto every failing element would make the API
	// reject duplicate names. The path is still reported, the value is not.
	plan := planFor(t, "object.metadata.namespace == 'kube-system' || object.spec.containers.all(c, c.name == 'sidecar')")
	require.NotNil(t, plan.elements)
	require.Len(t, plan.elements.fields, 1)
	assert.Equal(t, "name", plan.elements.fields[0].path)
	assert.Empty(t, plan.elements.fields[0].value, "an element value under an outer disjunction is an alternative, not a fix")
}

func TestPathPlanKeepsElementValueUnderScopeGuardDisjunction(t *testing.T) {
	// The shape the bundle actually uses: the comprehension sits under a kind
	// guard disjunction, whose only other branch reads object.kind. That is not
	// a competing fix, so the element value survives.
	plan := planFor(t, "object.kind != 'Pod' || object.spec.containers.all(c, has(c.securityContext) && c.securityContext.readOnlyRootFilesystem == true)")
	require.NotNil(t, plan.elements)
	require.Len(t, plan.elements.fields, 1)
	assert.Equal(t, "securityContext.readOnlyRootFilesystem", plan.elements.fields[0].path)
	assert.Equal(t, "true", plan.elements.fields[0].value, "a kind guard is not a competing alternative to the element requirement")
}

func TestPathPlanKeepsValueGuardedByPresenceTest(t *testing.T) {
	// The safe disjunction the bundle actually uses: the only other branch is a
	// presence test (and a scope guard) on the same field, neither of which is a
	// competing fix, so the equality stays a genuine requirement.
	plan := planFor(t, "object.kind != 'Pod' || !has(object.spec.hostNetwork) || object.spec.hostNetwork == false")
	require.Len(t, plan.direct, 1)
	assert.Equal(t, "spec.hostNetwork", plan.direct[0].path)
	assert.Equal(t, "false", plan.direct[0].value, "!has(x) || x == v is a requirement, not an alternative")
}

func TestPathPlanDropsValueUnderNegation(t *testing.T) {
	// The literal in `x == true` says what makes the expression true, not what
	// makes the policy pass, once a negation sits between the two.
	plan := planFor(t, "object.kind != 'Pod' || !(object.spec.hostNetwork == true)")
	require.Len(t, plan.direct, 1)
	assert.Equal(t, "spec.hostNetwork", plan.direct[0].path)
	assert.Empty(t, plan.direct[0].value, "a negated equality is not a value to write")
}

func TestPathPlanDropsValueForNonLiteralComparison(t *testing.T) {
	plan := planFor(t, "object.spec.replicas == params.settings.minReplicas")
	require.Len(t, plan.direct, 1)
	assert.Empty(t, plan.direct[0].value)
}

func TestPathPlanOfUncompilableExpressionIsEmpty(t *testing.T) {
	plan := planFor(t, "object.spec.((((")
	assert.Empty(t, plan.direct)
	assert.Nil(t, plan.elements)
}

// mixedFilesystemPod violates C-0017 through its first and third containers
// only: the second one sets readOnlyRootFilesystem and is compliant.
func mixedFilesystemPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "mixed", "namespace": "prod"},
		"spec": map[string]any{"containers": []any{
			map[string]any{"name": "no-context", "image": "nginx"},
			map[string]any{"name": "compliant", "image": "nginx", "securityContext": map[string]any{"readOnlyRootFilesystem": true}},
			map[string]any{"name": "writable", "image": "nginx", "securityContext": map[string]any{"readOnlyRootFilesystem": false}},
		}},
	}
}

func failingPaths(t *testing.T, controlID string, obj map[string]any) []PathHint {
	t.Helper()
	e, err := NewEvaluator()
	require.NoError(t, err)

	eval, err := e.EvaluateControl(context.Background(), controlID, obj, nil)
	require.NoError(t, err)
	require.True(t, eval.Applicable)

	var hints []PathHint
	for _, res := range eval.Results {
		require.NoError(t, res.Err)
		if !res.Passed {
			hints = append(hints, res.Paths...)
		}
	}
	return hints
}

func TestViolationPathsPinTheFailingElements(t *testing.T) {
	// The middle container satisfies the policy on its own, so it must not be
	// named: a scan that points a user at a compliant container is worse than
	// one that points at the list.
	assert.Equal(t, []PathHint{
		{Path: "spec.containers[0].securityContext.readOnlyRootFilesystem", Value: "true"},
		{Path: "spec.containers[2].securityContext.readOnlyRootFilesystem", Value: "true"},
	}, failingPaths(t, "C-0017", mixedFilesystemPod()))
}

// resolvePlan drives a plan's resolve against obj, re-evaluating expr for the
// per-element re-check the way the evaluator does at scan time.
func resolvePlan(t *testing.T, expr string, obj map[string]any) []PathHint {
	t.Helper()
	e, err := NewEvaluator()
	require.NoError(t, err)

	violates := func(candidate map[string]any) bool {
		activation := e.activationFor(context.Background(), candidate, nil, nil, nil)
		out, err := e.evalExpression(context.Background(), expr, activation)
		require.NoError(t, err)
		passed, ok := out.Value().(bool)
		require.True(t, ok)
		return !passed
	}
	return e.buildPathPlan(expr).resolve(obj, violates)
}

func TestViolationPathsBlameNoElementWhenAConjunctiveSiblingFails(t *testing.T) {
	// The comprehension is exact on its own, but a conjunctive sibling reads the
	// object and fails independently, so re-checking any single container still
	// fails. Emptying the list must reveal the sibling as the real cause and stop
	// every container from being blamed for a fix (readOnlyRootFilesystem) that
	// is not why the object failed.
	expr := "object.spec.hostNetwork == false && object.spec.containers.all(c, has(c.securityContext) && c.securityContext.readOnlyRootFilesystem == true)"
	obj := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p"},
		"spec": map[string]any{
			"hostNetwork": true, // the real failure, independent of any container
			"containers": []any{
				map[string]any{"name": "a", "securityContext": map[string]any{"readOnlyRootFilesystem": true}},
				map[string]any{"name": "b", "securityContext": map[string]any{"readOnlyRootFilesystem": true}},
			},
		},
	}

	hints := resolvePlan(t, expr, obj)
	for _, h := range hints {
		assert.NotContainsf(t, h.Path, "containers[", "a compliant container was blamed for a failure caused by hostNetwork: %s", h.Path)
	}
	assert.Contains(t, hints, PathHint{Path: "spec.hostNetwork", Value: "false"}, "the real cause is still reported")
}

func TestViolationPathsStillPinElementsWhenTheSiblingPasses(t *testing.T) {
	// Same shape, but the sibling (hostNetwork) is compliant, so the container is
	// the genuine cause and the empty-list guard must not suppress it.
	expr := "object.spec.hostNetwork == false && object.spec.containers.all(c, has(c.securityContext) && c.securityContext.readOnlyRootFilesystem == true)"
	obj := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p"},
		"spec": map[string]any{
			"hostNetwork": false,
			"containers": []any{
				map[string]any{"name": "a", "securityContext": map[string]any{"readOnlyRootFilesystem": true}},
				map[string]any{"name": "b"}, // the offender
			},
		},
	}

	assert.Contains(t, resolvePlan(t, expr, obj),
		PathHint{Path: "spec.containers[1].securityContext.readOnlyRootFilesystem", Value: "true"})
}

func TestViolationPathsBlameNoElementWhenTheFailureIsElsewhere(t *testing.T) {
	// C-0034 fails on the pod's own automountServiceAccountToken. Its
	// containers have nothing to do with the verdict and none is named.
	pod := mixedFilesystemPod()
	pod["spec"].(map[string]any)["automountServiceAccountToken"] = true

	assert.Equal(t, []PathHint{
		{Path: "spec.automountServiceAccountToken", Value: "false"},
	}, failingPaths(t, "C-0034", pod))
}

func TestConjunctiveFieldsAreAllReportedNotJustTheFailingOne(t *testing.T) {
	// Documents the known imprecision in resolve: the failing ELEMENT is pinned,
	// the failing FIELD among several conjunctive requirements is not. C-0038
	// requires both hostPID and hostIPC to be false; a Pod that sets only
	// hostPID still gets both paths, where Rego's host-pid-ipc-privileges has a
	// separate deny block per field and names only the one that failed.
	//
	// This is safe rather than merely tolerated: the value reported for hostIPC
	// is the value the policy requires there, so applying it cannot make the Pod
	// less compliant. If field-level pinning is added later this test should
	// change to expect only spec.hostPID.
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "hostpid", "namespace": "default"},
		"spec": map[string]any{
			"hostPID":    true, // the only violation; hostIPC is absent, so compliant
			"containers": []any{map[string]any{"name": "c", "image": "nginx"}},
		},
	}

	assert.Equal(t, []PathHint{
		{Path: "spec.hostIPC", Value: "false"},
		{Path: "spec.hostPID", Value: "false"},
	}, failingPaths(t, "C-0038", pod))
}

func TestPassingResultsCarryNoPaths(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	pod := mixedFilesystemPod()
	pod["spec"].(map[string]any)["containers"] = []any{
		map[string]any{"name": "compliant", "securityContext": map[string]any{"readOnlyRootFilesystem": true}},
	}

	eval, err := e.EvaluateControl(context.Background(), "C-0017", pod, nil)
	require.NoError(t, err)
	for _, res := range eval.Results {
		require.True(t, res.Passed)
		assert.Empty(t, res.Paths, "a passing validation has nothing to remediate")
	}
}

// pathlessPolicies are the bundle policies no path can be derived from, with
// the reason each one is exempt. Anything else that stops yielding a path is a
// regression in derivation or an upstream rewrite into a shape we cannot read,
// and TestEveryBundleValidationYieldsAPath turns that into a `make sync-vap`
// failure instead of findings that quietly lose their remediation paths.
//
// KNOWN LIMITATION for a future sync: the plan is derived from the validation
// expression's AST only, not from any `variables:` block it references. The
// embedded bundle inlines its object access today, but upstream controls are
// moving to the variables pattern; a validation whose object access lives in a
// variable (validation is just `variables.foo`) derives no path and will fail
// this test at sync time. That failure is the signal to either teach the
// derivation to inline variable definitions or exempt the policy here - not a
// silent loss of paths.
var pathlessPolicies = map[string]string{
	"cluster-policy-deny-attach":      "denies outright (the expression is the constant false), so there is no field to point at",
	"cluster-policy-deny-exec":        "denies outright, same as attach",
	"cluster-policy-deny-portforward": "denies outright, same as attach",

	"kubescape-c-0045-deny-workloads-with-hostpath-volumes-readonly-not-false":             "iterates both volumes and containers, so a failure cannot be attributed to either list",
	"kubescape-c-0076-deny-resources-without-configured-list-of-labels-not-set":            "iterates two label maps, and a map key is not a field path",
	"kubescape-c-0077-deny-resources-without-configured-list-of-k8s-common-labels-not-set": "iterates two label maps, same as C-0076",
}

func TestEveryBundleValidationYieldsAPath(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	catalog, err := getVAPCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, catalog.byName, "bundle parsed to no policies")

	for name, vap := range catalog.byName {
		for _, val := range vap.Validations {
			plan := e.buildPathPlan(val.Expression)
			if len(plan.direct) > 0 || (plan.elements != nil && len(plan.elements.fields) > 0) {
				continue
			}
			_, exempt := pathlessPolicies[name]
			assert.Truef(t, exempt,
				"no path could be derived from a validation of policy %q, so its failures would report where nothing went wrong; expression:\n%s\n"+
					"either restore the derivation or add the policy to pathlessPolicies with the reason it cannot carry paths", name, val.Expression)
		}
	}
}

func TestEveryDerivedBundlePathIsWellFormed(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	assertPath := func(policy, path string) {
		t.Helper()
		require.NotEmpty(t, path, "policy %q derived an empty path", policy)
		assert.NotContains(t, path, "..", "policy %q derived a path with an empty segment: %q", policy, path)
	}

	for name, vap := range catalog.byName {
		for _, val := range vap.Validations {
			plan := e.buildPathPlan(val.Expression)
			for _, ref := range plan.direct {
				assertPath(name, ref.path)
				// Object paths are what a user edits; the fields a policy reads
				// only to decide whether it covers this kind are not.
				assert.False(t, scopeGuardFields[ref.path], "policy %q derived the scope guard %q as a remediation path", name, ref.path)
			}
			if plan.elements == nil {
				continue
			}
			assertPath(name, plan.elements.collection)
			for _, ref := range plan.elements.fields {
				assertPath(name, ref.path)
			}
		}
	}
}

// bundleFixValues is every (path, value) pair the current bundle produces a fix
// value for, as "path=value" (element paths written "collection[].field=value").
// It is golden data on purpose. TestEveryBundleValidationYieldsAPath guards
// against LOSING a path; this guards against GAINING a wrong value, which is the
// direction the whole PR's risk argument points: a value is written into a
// user's YAML, so a make sync-vap that turns `== true` into `== false`, or
// introduces a fix for a field that is really one of several alternatives, has
// to fail a test rather than ship silently. Every entry here is a security
// field set to the one value that satisfies its control; if this list grows a
// path with a surprising value, that is the signal to look.
//
// Two absences are worth naming so a reader does not read them as bugs:
//   - spec.template.spec.hostIPC=false is missing because C-0038's workload
//     validation in this vendored bundle checks hostPID twice and never hostIPC.
//     The derivation reports exactly what the expression says. That policy bug is
//     already fixed on cel-admission-library main and only survives here because
//     the pinned release predates the fix, so this entry comes back on its own
//     once CEL_LIBRARY_VERSION is bumped - no upstream issue to chase.
//   - C-0075's imagePullPolicy=Always is missing because its element predicate
//     `!c.image.endsWith(':latest') || c.imagePullPolicy == 'Always'` puts the
//     equality under a disjunction: retagging the image satisfies the policy
//     just as well as setting the pull policy, so neither is a value to write
//     (see valueIsRequirement). This is NOT a parity gap. The Rego rule
//     (regolibrary image-pull-policy-is-not-set-to-always) reaches the same
//     conclusion by hand: all three of its deny blocks emit image and
//     imagePullPolicy as reviewPaths with an empty fixPaths. So a CEL finding
//     and its Rego equivalent flag the same two fields for review, neither
//     offering a value, which is the behaviour a human rule author chose for
//     this shape too.
var bundleFixValues = []string{
	"automountServiceAccountToken=false",
	"spec.automountServiceAccountToken=false",
	"spec.containers[].securityContext.allowPrivilegeEscalation=false",
	"spec.containers[].securityContext.readOnlyRootFilesystem=true",
	"spec.hostIPC=false",
	"spec.hostNetwork=false",
	"spec.hostPID=false",
	"spec.jobTemplate.spec.automountServiceAccountToken=false",
	"spec.jobTemplate.spec.template.spec.containers[].securityContext.allowPrivilegeEscalation=false",
	"spec.jobTemplate.spec.template.spec.containers[].securityContext.readOnlyRootFilesystem=true",
	"spec.jobTemplate.spec.template.spec.hostIPC=false",
	"spec.jobTemplate.spec.template.spec.hostNetwork=false",
	"spec.jobTemplate.spec.template.spec.hostPID=false",
	"spec.template.spec.automountServiceAccountToken=false",
	"spec.template.spec.containers[].securityContext.allowPrivilegeEscalation=false",
	"spec.template.spec.containers[].securityContext.readOnlyRootFilesystem=true",
	"spec.template.spec.hostNetwork=false",
	"spec.template.spec.hostPID=false",
}

func TestEveryBundleFixValueIsExpected(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, vap := range catalog.byName {
		for _, val := range vap.Validations {
			plan := e.buildPathPlan(val.Expression)
			for _, ref := range plan.direct {
				if ref.value != "" {
					seen[ref.path+"="+ref.value] = true
				}
			}
			if plan.elements == nil {
				continue
			}
			for _, ref := range plan.elements.fields {
				if ref.value != "" {
					seen[plan.elements.collection+"[]."+ref.path+"="+ref.value] = true
				}
			}
		}
	}

	got := make([]string, 0, len(seen))
	for pair := range seen {
		got = append(got, pair)
	}
	sort.Strings(got)

	assert.Equal(t, bundleFixValues, got,
		"the set of fix values the bundle produces changed; if a make sync-vap added or altered a value, confirm it is a genuine requirement (not one of several alternatives) before updating bundleFixValues")
}
