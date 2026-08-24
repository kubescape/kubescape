package cel

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// costOf measures what one expression actually costs against an object, so the
// budget tests can be calibrated from the runtime instead of from magic numbers
// that would drift the next time cel-go retunes its cost model.
func costOf(t *testing.T, e *Evaluator, expr string, obj map[string]any, variables []Variable) int64 {
	t.Helper()
	activation := e.activationFor(context.Background(), obj, nil, nil, variables, nil)
	prog, err := e.programs.get(expr)
	require.NoError(t, err)
	_, details, err := e.run(context.Background(), prog, activation)
	require.NoError(t, err)
	require.NotNil(t, details, "base env must track cost")
	actual := details.ActualCost()
	require.NotNil(t, actual)
	// Bounds-checked the same way charge does, so the helper cannot be the one
	// place an overflowing cost slips through untyped.
	require.LessOrEqual(t, *actual, uint64(math.MaxInt64), "cost does not fit int64")
	cost := int64(math.MaxInt64)
	if *actual <= math.MaxInt64 {
		cost = int64(*actual)
	}
	return cost
}

func budgetPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p", "namespace": "default"},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers": []any{
				map[string]any{"name": "a", "image": "nginx"},
				map[string]any{"name": "b", "image": "nginx"},
			},
		},
	}
}

func TestDefaultBudgetMatchesTheApiserverRuntimeBudget(t *testing.T) {
	// The whole point of the shared budget is that we spend what admission
	// spends, so the default has to be the apiserver's constant, not a number
	// of our own choosing.
	e, err := NewEvaluator()
	require.NoError(t, err)
	assert.Equal(t, int64(celconfig.RuntimeCELCostBudget), e.budgetLimit())

	tuned, err := NewEvaluator(WithCostBudget(42))
	require.NoError(t, err)
	assert.Equal(t, int64(42), tuned.budgetLimit())
}

func TestBudgetIsSharedAcrossValidations(t *testing.T) {
	// Two validations that each fit the per-expression limit easily but do not
	// both fit the shared budget. This is the divergence the PR exists for: the
	// base env's per-call limit says both are fine, admission says the policy is
	// too expensive.
	obj := budgetPod()
	first := "object.spec.hostNetwork == false"
	second := "object.spec.containers.all(c, c.image != 'nginx')"

	e, err := NewEvaluator()
	require.NoError(t, err)
	firstCost := costOf(t, e, first, obj, nil)
	require.Greater(t, firstCost, int64(0))

	// Exactly enough for the first expression and nothing after it.
	metered, err := NewEvaluator(WithCostBudget(firstCost))
	require.NoError(t, err)
	results, err := metered.EvaluateOnObject(context.Background(), obj, nil, nil, nil,
		[]Validation{{Expression: first, Message: "host network"}, {Expression: second, Message: "image"}})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// The first validation still reports its real verdict. Losing a confirmed
	// violation because a later expression ran long would be a regression of
	// the per-resource outcome handling.
	assert.NoError(t, results[0].Err)
	assert.False(t, results[0].Passed)
	assert.Equal(t, "host network", results[0].Message)

	// The second never ran, and reads as unknown rather than as a pass.
	require.Error(t, results[1].Err)
	assert.True(t, errors.Is(results[1].Err, errOutOfBudget))
	assert.False(t, results[1].Passed)
}

func TestBudgetThatCoversEverythingChangesNothing(t *testing.T) {
	obj := budgetPod()
	first := "object.spec.hostNetwork == false"
	second := "object.spec.containers.all(c, c.image != 'nginx')"

	e, err := NewEvaluator()
	require.NoError(t, err)
	total := costOf(t, e, first, obj, nil) + costOf(t, e, second, obj, nil)

	metered, err := NewEvaluator(WithCostBudget(total))
	require.NoError(t, err)
	results, err := metered.EvaluateOnObject(context.Background(), obj, nil, nil, nil,
		[]Validation{{Expression: first}, {Expression: second}})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for i, res := range results {
		assert.NoError(t, res.Err, "validation %d", i)
		assert.False(t, res.Passed, "validation %d", i)
	}
}

func TestVariableCostIsChargedToTheBudget(t *testing.T) {
	// A variable evaluates inside the validation that first reads it, so its
	// cost has to land on the same budget. If it did not, a policy could push
	// arbitrary work into variables: and scan under a budget admission never
	// grants it.
	obj := budgetPod()
	vars := []Variable{{Name: "hostNet", Expression: "object.spec.hostNetwork"}}
	validation := "variables.hostNet == false"

	e, err := NewEvaluator()
	require.NoError(t, err)
	validationCost := costOf(t, e, validation, obj, vars)
	variableCost := costOf(t, e, vars[0].Expression, obj, nil)
	require.Greater(t, variableCost, int64(0), "variable must cost something for this test to mean anything")

	// Budget covers the validation but not the variable it pulls in.
	tight, err := NewEvaluator(WithCostBudget(validationCost))
	require.NoError(t, err)
	results, err := tight.EvaluateOnObject(context.Background(), obj, nil, nil, vars,
		[]Validation{{Expression: validation}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Error(t, results[0].Err)
	assert.True(t, errors.Is(results[0].Err, errOutOfBudget))

	// Budget covers both, so the same policy evaluates cleanly.
	enough, err := NewEvaluator(WithCostBudget(validationCost + variableCost))
	require.NoError(t, err)
	results, err = enough.EvaluateOnObject(context.Background(), obj, nil, nil, vars,
		[]Validation{{Expression: validation}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Err)
	assert.False(t, results[0].Passed)
}

func TestMemoizedVariableIsChargedOnce(t *testing.T) {
	// Two validations read the same variable. It evaluates once and is charged
	// once, exactly as the apiserver's composition map behaves, so a budget
	// sized for one copy of the variable is enough.
	obj := budgetPod()
	vars := []Variable{{Name: "hostNet", Expression: "object.spec.hostNetwork"}}
	first := "variables.hostNet == false"
	second := "variables.hostNet != true"

	e, err := NewEvaluator()
	require.NoError(t, err)
	budget := costOf(t, e, first, obj, vars) +
		costOf(t, e, second, obj, vars) +
		costOf(t, e, vars[0].Expression, obj, nil)

	metered, err := NewEvaluator(WithCostBudget(budget))
	require.NoError(t, err)
	results, err := metered.EvaluateOnObject(context.Background(), obj, nil, nil, vars,
		[]Validation{{Expression: first}, {Expression: second}})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for i, res := range results {
		assert.NoError(t, res.Err, "validation %d charged a second time for the same variable", i)
	}
}

func TestPathDerivationDoesNotSpendTheBudget(t *testing.T) {
	// Deriving remediation paths re-runs the validation once per container plus
	// one baseline check. Admission never does that work, so charging it here
	// would turn a violation admission accepts into an unknown verdict on any
	// object with a few containers.
	obj := budgetPod()
	validation := "object.spec.containers.all(c, c.image != 'nginx')"

	e, err := NewEvaluator()
	require.NoError(t, err)
	cost := costOf(t, e, validation, obj, nil)

	// Exactly one expression's worth of budget, with three re-runs to come.
	metered, err := NewEvaluator(WithCostBudget(cost))
	require.NoError(t, err)
	results, err := metered.EvaluateOnObject(context.Background(), obj, nil, nil, nil,
		[]Validation{{Expression: validation, Message: "bad image"}})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.NoError(t, results[0].Err)
	assert.False(t, results[0].Passed)
	assert.NotEmpty(t, results[0].Paths, "paths must still be derived on an exhausted budget")
}

func TestCompileFailureLeavesTheBudgetToTheRestOfThePolicy(t *testing.T) {
	// An expression that does not compile never ran, so it spent nothing. Charging
	// it would latch the budget and take every later validation down with it,
	// while admission returns on the compile error before it touches the budget
	// and keeps going. authorizer is deliberately undeclared in NewEnv, so a
	// policy referencing it is exactly the "should fail to compile and get
	// skipped" case env.go describes.
	obj := budgetPod()
	broken := "authorizer.group('').resource('pods').check('create').allowed()"

	e, err := NewEvaluator()
	require.NoError(t, err)
	results, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, nil, []Validation{
		{Expression: broken},
		{Expression: "object.spec.hostNetwork == false", Message: "host network"},
		{Expression: "object.metadata.name == 'p'"},
	})
	require.NoError(t, err)
	require.Len(t, results, 3)

	// The compile error is what the caller gets, not an out-of-budget error
	// standing in for it.
	require.Error(t, results[0].Err)
	assert.False(t, errors.Is(results[0].Err, errOutOfBudget), "a compile failure must not read as an exhausted budget")
	assert.Contains(t, results[0].Err.Error(), "compile")

	// And the validations after it still get real verdicts.
	assert.NoError(t, results[1].Err)
	assert.False(t, results[1].Passed)
	assert.Equal(t, "host network", results[1].Message)
	assert.NoError(t, results[2].Err)
	assert.True(t, results[2].Passed)
}

func TestVariableCompileFailureOnlyBreaksItsOwnValidation(t *testing.T) {
	// Same rule on the variable path: a variable that never compiled has no cost
	// to report, so the validation that read it must name the compile failure
	// rather than a missing cost report, and validations that never touched it
	// must be unaffected.
	obj := budgetPod()
	vars := []Variable{{Name: "bad", Expression: "authorizer.group('')"}}

	e, err := NewEvaluator()
	require.NoError(t, err)
	results, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, vars, []Validation{
		{Expression: "variables.bad == 1"},
		{Expression: "object.spec.hostNetwork == false"},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.Error(t, results[0].Err)
	assert.Contains(t, results[0].Err.Error(), "compile")
	assert.False(t, errors.Is(results[0].Err, errOutOfBudget))

	assert.NoError(t, results[1].Err)
	assert.False(t, results[1].Passed)
}

func TestCancelledContextInterruptsAComprehension(t *testing.T) {
	// Guards cel.InterruptCheckFrequency being set on every program. Without it
	// cel-go never plans an interruptable evaluation, and ContextEval ignores a
	// cancelled context completely: it checks nothing before evaluating and
	// nothing during, so a comprehension over a long list runs to completion
	// whatever the caller does. The list is longer than CheckFrequency so the
	// runtime reaches at least one check.
	//
	// This goes at one expression rather than through EvaluateOnObject, which
	// would refuse a cancelled context before evaluating anything (see the test
	// below) and so would pass with or without the program option.
	items := make([]any, 0, 5*celconfig.CheckFrequency)
	for i := 0; i < 5*celconfig.CheckFrequency; i++ {
		items = append(items, map[string]any{"name": "c", "image": "nginx"})
	}
	obj := map[string]any{"kind": "Pod", "spec": map[string]any{"containers": items}}

	e, err := NewEvaluator()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = e.evalExpression(ctx, "object.spec.containers.all(c, c.image == 'nginx')",
		e.activationFor(ctx, obj, nil, nil, nil, nil), nil)
	require.Error(t, err, "a cancelled scan must not keep evaluating CEL")
	assert.ErrorIs(t, err, context.Canceled)
}

// TestCancelledContextIsNotAnExpressionError is the regression for the
// failurePolicy fix: a cancellation that fires while a validation expression is
// evaluating must NOT be classified as an expressionError, or failurePolicy Fail
// would turn a cancelled scan into a false deny. ContextEval only notices a
// cancelled context every CheckFrequency steps INSIDE a comprehension, so
// pre-cancelling still exercises the mid-evaluation interrupt path (the same one
// a Ctrl+C during a long comprehension hits), while calling evalExpression
// directly bypasses the between-validations ctx.Err() guard that would mask the
// bug.
func TestCancelledContextIsNotAnExpressionError(t *testing.T) {
	items := make([]any, 0, 5*celconfig.CheckFrequency)
	for i := 0; i < 5*celconfig.CheckFrequency; i++ {
		items = append(items, map[string]any{"name": "c", "image": "nginx"})
	}
	obj := map[string]any{"kind": "Pod", "spec": map[string]any{"containers": items}}

	e, err := NewEvaluator()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = e.evalExpression(ctx, "object.spec.containers.all(c, c.image == 'nginx')",
		e.activationFor(ctx, obj, nil, nil, nil, nil), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, IsExpressionError(err),
		"a cancelled scan must stay skipped, never become a deny")
}

// TestCancelledVariableIsNotAnExpressionError covers the same classification on
// the lazy-variable path: a variable whose evaluation is cut short by a
// cancellation surfaces as an error to the validation that references it, and
// that error must still read as a cancellation (not an expressionError) so it is
// skipped rather than denied.
func TestCancelledVariableIsNotAnExpressionError(t *testing.T) {
	items := make([]any, 0, 5*celconfig.CheckFrequency)
	for i := 0; i < 5*celconfig.CheckFrequency; i++ {
		items = append(items, map[string]any{"name": "c", "image": "nginx"})
	}
	obj := map[string]any{"kind": "Pod", "spec": map[string]any{"containers": items}}
	variables := []Variable{{Name: "all", Expression: "object.spec.containers.all(c, c.image == 'nginx')"}}
	validations := []Validation{{Expression: "variables.all == true"}}

	e, err := NewEvaluator()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := e.evaluateValidation(ctx, validations[0], e.activationFor(ctx, obj, nil, nil, variables, nil), nil)
	require.Error(t, res.Err)
	assert.False(t, IsExpressionError(res.Err),
		"a cancelled variable evaluation must not become a deny")
}

func TestCancelledContextStopsTheRemainingValidations(t *testing.T) {
	// InterruptCheckFrequency only makes the runtime check every N steps INSIDE
	// one evaluation, so an ordinary policy of cheap expressions would run every
	// one of them to completion after Ctrl+C. A scan over thousands of objects
	// has to stop on the spot instead, whatever shape its expressions are.
	e, err := NewEvaluator()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := e.EvaluateOnObject(ctx, budgetPod(), nil, nil, nil, []Validation{
		{Expression: "object.spec.hostNetwork == false"},
		{Expression: "object.metadata.name == 'p'"},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for i, res := range results {
		require.Error(t, res.Err, "validation %d kept evaluating after cancellation", i)
		assert.ErrorIs(t, res.Err, context.Canceled)
		assert.False(t, res.Passed, "validation %d", i)
	}
}
