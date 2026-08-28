package cel

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

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
			// when evaluated. It is still evaluated -- see
			// TestMatchConditionsHoldEvaluatesEveryConditionEvenAfterFalse for why
			// that matters -- but a false condition outranks an error however they
			// are ordered, so the verdict is a clean not-matched either way.
			name: "a false condition outranks a later condition that errors",
			conditions: []MatchCondition{
				cond("is-kube-system", "object.metadata.namespace == 'kube-system'"),
				cond("would-error", "object.spec.nodeName == 'node-1'"),
			},
			matched: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := e.matchConditionsHold(context.Background(), tc.conditions, gatedPod(), nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.matched, matched)
		})
	}
}

// TestMatchConditionsHoldFalseOutranksError pins the apiserver's precedence: a
// condition evaluating to false skips the policy whatever order it appears in
// relative to a condition that errored, and only a gate of trues and errors
// reaches failurePolicy. Returning on the first error instead would deny an
// object under Fail that admission simply skips.
func TestMatchConditionsHoldFalseOutranksError(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	isFalse := cond("is-kube-system", "object.metadata.namespace == 'kube-system'")
	// Selects a field the object does not carry, so it errors at eval time.
	evalErrors := cond("absent-field", "object.spec.nodeName == 'node-1'")
	// authorizer is not declared on the env, so this cannot compile.
	wontCompile := cond("uncompilable", "authorizer.group('').resource('pods').check('list').allowed()")

	cases := []struct {
		name       string
		conditions []MatchCondition
	}{
		{
			name:       "an eval error before a false one is discarded",
			conditions: []MatchCondition{evalErrors, isFalse},
		},
		{
			name:       "a compile error before a false one is discarded",
			conditions: []MatchCondition{wontCompile, isFalse},
		},
		{
			name:       "the false one still wins from further down the gate",
			conditions: []MatchCondition{cond("is-pod", "object.kind == 'Pod'"), evalErrors, isFalse},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := e.matchConditionsHold(context.Background(), tc.conditions, gatedPod(), nil, nil)
			require.NoError(t, err, "a false condition outranks an error, so the gate is a clean not-matched")
			assert.False(t, matched)
		})
	}

	t.Run("trues and errors with no false still surface the error", func(t *testing.T) {
		matched, err := e.matchConditionsHold(context.Background(), []MatchCondition{
			cond("is-pod", "object.kind == 'Pod'"),
			evalErrors,
		}, gatedPod(), nil, nil)
		require.Error(t, err, "with no false condition the error is what failurePolicy acts on")
		assert.False(t, matched)
		assert.True(t, IsExpressionError(err))
		assert.Contains(t, err.Error(), evalErrors.Name)
	})
}

// TestMatchConditionsHoldReadsPolicyInputs proves the gate evaluates against the
// bindings admission gives a matchCondition, so a condition can narrow on any of
// them. namespaceObject is not among them - see
// TestMatchConditionsHoldBindsNamespaceObjectNull.
func TestMatchConditionsHoldReadsPolicyInputs(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	params := map[string]any{"settings": map[string]any{"gate": true}}
	variables := []Variable{{Name: "isProd", Expression: "object.metadata.namespace == 'prod'"}}

	conditions := []MatchCondition{
		cond("via-variable", "variables.isProd"),
		cond("via-params", "params.settings.gate"),
		cond("via-request", "request.operation == 'CREATE'"),
	}

	matched, err := e.matchConditionsHold(context.Background(), conditions, gatedPod(), params, variables)
	require.NoError(t, err)
	assert.True(t, matched)
}

// TestMatchConditionsHoldBindsNamespaceObjectNull pins the one binding the gate
// deliberately withholds. The apiserver's matcher evaluates matchConditions with
// a hardcoded nil namespace even when the VAP dispatcher has already resolved
// the real one for spec.validations, so at admission a condition reading
// namespaceObject.* always errors into failurePolicy. Answering it offline from
// the scan's real Namespace would pass a policy admission rejects, so the gate
// must reproduce the error - and it must stay an expression error, since that is
// the verdict failurePolicy governs.
func TestMatchConditionsHoldBindsNamespaceObjectNull(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	// matchConditionsHold takes no namespaceObject at all, so a caller holding a
	// real Namespace (EvaluateControl does, for the validations) has no way to
	// reach the gate with it. The condition below therefore runs against null.
	conditions := []MatchCondition{cond("via-namespace", "namespaceObject.metadata.labels.tier == 'critical'")}

	matched, err := e.matchConditionsHold(context.Background(), conditions, gatedPod(), nil, nil)
	require.Error(t, err, "namespaceObject is null at admission, so the condition errors rather than answering")
	assert.False(t, matched)
	assert.True(t, IsExpressionError(err), "the error is one failurePolicy governs, as at admission")
	assert.Contains(t, err.Error(), "via-namespace")
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
			matched, err := e.matchConditionsHold(context.Background(), []MatchCondition{tc.condition}, gatedPod(), nil, nil)
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

	matched, err := e.matchConditionsHold(ctx, []MatchCondition{cond("is-pod", "object.kind == 'Pod'")}, gatedPod(), nil, nil)
	require.Error(t, err)
	assert.False(t, matched)
	assert.False(t, IsExpressionError(err), "a cancelled scan is not a verdict failurePolicy governs")
}

// TestMatchConditionsHoldEvaluatesEveryConditionEvenAfterFalse is the direct
// regression test for the divergence from the apiserver's real matcher: a
// false condition must not stop the gate from evaluating (and charging the
// shared budget for) the conditions after it, because the apiserver's own
// ForInput evaluates every condition unconditionally before Match ever picks
// a verdict from the results. A condition expensive enough to exhaust the
// budget on its own, placed after an already-false condition, must still
// exhaust it and produce the terminal budget error -- not a clean,
// budget-untouched not-matched skip.
func TestMatchConditionsHoldEvaluatesEveryConditionEvenAfterFalse(t *testing.T) {
	// A single "object.metadata.namespace == '...'" condition costs 4 units
	// (measured directly against this evaluator). A budget of 5 leaves the
	// first condition just enough to succeed (remaining: 1), with too little
	// left for the identical second condition to also complete.
	e, err := NewEvaluator(WithCostBudget(5))
	require.NoError(t, err)

	isFalse := cond("is-kube-system", "object.metadata.namespace == 'kube-system'")
	wouldExhaust := cond("is-prod", "object.metadata.namespace == 'prod'")

	matched, err := e.matchConditionsHold(context.Background(), []MatchCondition{isFalse, wouldExhaust}, gatedPod(), nil, nil)

	require.Error(t, err, "the second condition must still be evaluated and exhaust the budget, matching the apiserver's ForInput")
	assert.False(t, matched)
	assert.False(t, IsExpressionError(err), "budget exhaustion is terminal, not a retained expression error a false could outrank")
}

// TestMatchConditionsHoldOwnBudget proves the gate does not spend the budget the
// validations run on. The evaluator is capped so low that a single condition
// exhausts it; the validations that follow must still reach clean verdicts, which
// they only can on a budget of their own.
func TestMatchConditionsHoldOwnBudget(t *testing.T) {
	e, err := NewEvaluator(WithCostBudget(1))
	require.NoError(t, err)

	// A false condition after the exhausted one must NOT rescue the gate: once
	// the budget is gone nothing later can be trusted to have really evaluated,
	// so an exhausted budget is terminal where an expression error is not.
	_, err = e.matchConditionsHold(context.Background(), []MatchCondition{
		cond("is-prod", "object.metadata.namespace == 'prod'"),
		cond("is-kube-system", "object.metadata.namespace == 'kube-system'"),
	}, gatedPod(), nil, nil)
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

// TestMatchConditionsBudgetLimit pins the gate to the budget the apiserver bills
// matchConditions against, which is a quarter of the validations' ceiling.
// Metering the gate against the larger one would let a gate run offline that
// admission cuts off.
func TestMatchConditionsBudgetLimit(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	assert.Equal(t, int64(celconfig.RuntimeCELCostBudgetMatchConditions), e.matchConditionsBudgetLimit())
	assert.Less(t, e.matchConditionsBudgetLimit(), e.budgetLimit(), "the gate gets the smaller ceiling")

	overridden, err := NewEvaluator(WithCostBudget(7))
	require.NoError(t, err)
	assert.Equal(t, int64(7), overridden.matchConditionsBudgetLimit(), "an explicit override still wins")
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
