package cel

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedPod is the object the matchCondition tests gate on.
func gatedPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "gated", "namespace": "prod"},
		"spec":       map[string]any{"containers": []any{map[string]any{"name": "c", "image": "nginx"}}},
	}
}

func cond(name, expr string) MatchCondition {
	return MatchCondition{Name: name, Expression: expr}
}

// TestMatchConditionsHold pins the gate's verdicts: a policy runs only when every
// condition is true, and the first false one short-circuits the rest.
func TestMatchConditionsHold(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	cases := []struct {
		name       string
		conditions []MatchCondition
		matched    bool
	}{
		{
			name:       "no conditions match everything",
			conditions: nil,
			matched:    true,
		},
		{
			name: "every condition true matches",
			conditions: []MatchCondition{
				cond("is-pod", "object.kind == 'Pod'"),
				cond("is-prod", "object.metadata.namespace == 'prod'"),
			},
			matched: true,
		},
		{
			name: "one false condition does not match",
			conditions: []MatchCondition{
				cond("is-pod", "object.kind == 'Pod'"),
				cond("is-kube-system", "object.metadata.namespace == 'kube-system'"),
			},
			matched: false,
		},
		{
			// The second condition selects a field that is absent, which errors
			// when evaluated. A clean not-matched verdict therefore proves the
			// first false condition short-circuited it, as the apiserver does.
			name: "a false condition short-circuits the ones after it",
			conditions: []MatchCondition{
				cond("is-kube-system", "object.metadata.namespace == 'kube-system'"),
				cond("would-error", "object.spec.nodeName == 'node-1'"),
			},
			matched: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := e.matchConditionsHold(context.Background(), tc.conditions, gatedPod(), nil, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.matched, matched)
		})
	}
}

// TestMatchConditionsHoldReadsPolicyInputs proves the gate evaluates against the
// same bindings a validation gets, so a condition can narrow on any of them.
func TestMatchConditionsHoldReadsPolicyInputs(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	namespaceObject := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": "prod", "labels": map[string]any{"tier": "critical"}},
	}
	params := map[string]any{"settings": map[string]any{"gate": true}}
	variables := []Variable{{Name: "isProd", Expression: "object.metadata.namespace == 'prod'"}}

	conditions := []MatchCondition{
		cond("via-variable", "variables.isProd"),
		cond("via-params", "params.settings.gate"),
		cond("via-request", "request.operation == 'CREATE'"),
		cond("via-namespace", "namespaceObject.metadata.labels.tier == 'critical'"),
	}

	matched, err := e.matchConditionsHold(context.Background(), conditions, gatedPod(), namespaceObject, params, variables)
	require.NoError(t, err)
	assert.True(t, matched)
}

// TestMatchConditionsHoldErrors separates the errors failurePolicy governs from
// the ones it must not. A condition the expression itself broke is a verdict
// admission can reach; one that never compiled is offline-only.
func TestMatchConditionsHoldErrors(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	cases := []struct {
		name            string
		condition       MatchCondition
		expressionError bool
	}{
		{
			name:            "a non-bool result is an expression error",
			condition:       cond("not-bool", "object.metadata.name"),
			expressionError: true,
		},
		{
			name:            "selecting an absent field is an expression error",
			condition:       cond("absent", "object.spec.nodeName == 'node-1'"),
			expressionError: true,
		},
		{
			// authorizer is deliberately not declared on the env, so a condition
			// using it cannot compile. Admission never reaches this, so it must
			// stay outside failurePolicy's reach.
			name:            "an expression that will not compile is not an expression error",
			condition:       cond("uncompilable", "authorizer.group('').resource('pods').check('list').allowed()"),
			expressionError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := e.matchConditionsHold(context.Background(), []MatchCondition{tc.condition}, gatedPod(), nil, nil, nil)
			require.Error(t, err)
			assert.False(t, matched)
			assert.Contains(t, err.Error(), tc.condition.Name, "the error must name the condition")
			assert.Equal(t, tc.expressionError, IsExpressionError(err))
		})
	}
}

// TestMatchConditionsHoldCancellation proves a cancelled scan stops the gate and
// reports an unknown verdict rather than a not-matched one, which would silently
// drop the resource from the results.
func TestMatchConditionsHoldCancellation(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	matched, err := e.matchConditionsHold(ctx, []MatchCondition{cond("is-pod", "object.kind == 'Pod'")}, gatedPod(), nil, nil, nil)
	require.Error(t, err)
	assert.False(t, matched)
	assert.False(t, IsExpressionError(err), "a cancelled scan is not a verdict failurePolicy governs")
}

// TestMatchConditionsHoldOwnBudget proves the gate does not spend the budget the
// validations run on. The evaluator is capped so low that a single condition
// exhausts it; the validations that follow must still reach clean verdicts, which
// they only can on a budget of their own.
func TestMatchConditionsHoldOwnBudget(t *testing.T) {
	e, err := NewEvaluator(WithCostBudget(1))
	require.NoError(t, err)

	_, err = e.matchConditionsHold(context.Background(), []MatchCondition{
		cond("is-prod", "object.metadata.namespace == 'prod'"),
	}, gatedPod(), nil, nil, nil)
	require.Error(t, err, "the gate must exhaust this budget for the test to mean anything")
	assert.False(t, IsExpressionError(err))

	results, err := e.EvaluateOnObject(context.Background(), gatedPod(), nil, nil, nil, []Validation{
		{Expression: "true"},
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Err, "the gate must not have spent the validations' budget")
	assert.True(t, results[0].Passed)
}

// TestMatchConditionsGate maps a gate that reached no verdict onto the outcome
// admission produces, which is the whole reason failurePolicy is carried.
func TestMatchConditionsGate(t *testing.T) {
	failing := &VAP{ControlID: "C-1001", failurePolicy: admissionregistrationv1.Fail}
	ignoring := &VAP{ControlID: "C-1001", failurePolicy: admissionregistrationv1.Ignore}
	exprErr := &expressionError{assert.AnError}

	t.Run("failurePolicy Fail denies the object", func(t *testing.T) {
		eval := matchConditionsGate(failing, exprErr)
		assert.True(t, eval.Applicable)
		assert.True(t, eval.FailOnError)
		require.Len(t, eval.Results, 1)
		assert.Equal(t, exprErr, eval.Results[0].Err)
	})

	t.Run("failurePolicy Ignore skips the policy", func(t *testing.T) {
		eval := matchConditionsGate(ignoring, exprErr)
		assert.False(t, eval.Applicable)
		assert.Empty(t, eval.Results)
	})

	t.Run("an offline-only failure stays unknown under Ignore", func(t *testing.T) {
		// Admission never reaches a compile error, so failurePolicy does not
		// apply: the resource must surface as unknown, not be dropped as
		// not-matched the way an Ignore'd expression error is.
		eval := matchConditionsGate(ignoring, assert.AnError)
		assert.True(t, eval.Applicable)
		assert.False(t, eval.FailOnError)
		require.Len(t, eval.Results, 1)
		assert.Equal(t, assert.AnError, eval.Results[0].Err)
	})
}
