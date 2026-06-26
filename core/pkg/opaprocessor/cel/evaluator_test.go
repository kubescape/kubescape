package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostNetworkPod is a Pod that sets hostNetwork, used as a deliberate violation
// of "object.spec.hostNetwork == false".
func hostNetworkPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "production",
		},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers": []any{
				map[string]any{"name": "app", "image": "nginx:1.25"},
				map[string]any{"name": "sidecar", "image": ""},
			},
		},
	}
}

func TestEvaluateOnObjectFailingValidation(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{Expression: "object.spec.hostNetwork == false", Message: "host network is not allowed"},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Passed)
	assert.NoError(t, results[0].Err)
	assert.Equal(t, "host network is not allowed", results[0].Message)
}

func TestEvaluateOnObjectPassingValidation(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "nginx", "namespace": "production"},
		"spec":       map[string]any{"hostNetwork": false},
	}

	validations := []Validation{{Expression: "object.spec.hostNetwork == false"}}

	results, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].Passed)
	assert.NoError(t, results[0].Err)
	assert.Empty(t, results[0].Message)
}

// TestEvaluateOnObjectVariables proves variables are evaluated first and bound
// under variables.<name> so a validation can reference them.
func TestEvaluateOnObjectVariables(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	variables := []Variable{
		{Name: "containers", Expression: "object.spec.containers"},
	}
	validations := []Validation{
		{Expression: "variables.containers.all(c, c.image != '')", Message: "every container needs an image"},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, variables, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// The sidecar has an empty image, so the all() is false: a violation.
	assert.False(t, results[0].Passed)
	assert.NoError(t, results[0].Err)
	assert.Equal(t, "every container needs an image", results[0].Message)
}

// TestEvaluateOnObjectVariableChain proves a later variable can read an earlier
// one through the shared variables map.
func TestEvaluateOnObjectVariableChain(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	variables := []Variable{
		{Name: "containers", Expression: "object.spec.containers"},
		{Name: "count", Expression: "size(variables.containers)"},
	}
	validations := []Validation{
		{Expression: "variables.count == 2"},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, variables, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
	assert.NoError(t, results[0].Err)
}

func TestEvaluateOnObjectMessageExpression(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{
			Expression:        "object.spec.hostNetwork == false",
			MessageExpression: "'pod ' + object.metadata.name + ' uses host network'",
		},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.Equal(t, "pod nginx uses host network", results[0].Message)
}

// TestEvaluateOnObjectMessageExpressionWinsOverStatic pins the apiserver
// precedence: when both are set and messageExpression succeeds, it is used, not
// the static Message.
func TestEvaluateOnObjectMessageExpressionWinsOverStatic(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{
			Expression:        "object.spec.hostNetwork == false",
			Message:           "static message",
			MessageExpression: "'dynamic ' + object.metadata.name",
		},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.Equal(t, "dynamic nginx", results[0].Message)
}

// TestEvaluateOnObjectBrokenMessageExpressionStaysViolation is the key semantic
// guard: a failing messageExpression must NOT turn a real violation into an
// error. messageExpression is tried first (per apiserver precedence), errors,
// and falls back to the static Message while the violation stands.
func TestEvaluateOnObjectBrokenMessageExpressionStaysViolation(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{
			Expression:        "object.spec.hostNetwork == false",
			Message:           "host network is not allowed",
			MessageExpression: "object.spec.thisKeyDoesNotExist.value", // errors at eval
		},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Passed, "still a violation")
	assert.NoError(t, results[0].Err, "broken messageExpression must not become an error")
	assert.Equal(t, "host network is not allowed", results[0].Message)
}

// TestEvaluateOnObjectBrokenMessageExpressionNoStaticFallsToDefault checks the
// final fallback when there is no static Message either.
func TestEvaluateOnObjectBrokenMessageExpressionNoStaticFallsToDefault(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{
			Expression:        "object.spec.hostNetwork == false",
			MessageExpression: "object.spec.thisKeyDoesNotExist.value",
		},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.NoError(t, results[0].Err)
	assert.Equal(t, "failed expression: object.spec.hostNetwork == false", results[0].Message)
}

// TestEvaluateOnObjectNonBoolErrors guards that a validation expression that
// does not return bool is reported as Err, never as a silent pass.
func TestEvaluateOnObjectNonBoolErrors(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{{Expression: "object.metadata.name"}} // returns string

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Error(t, results[0].Err)
	assert.False(t, results[0].Passed)
}

// TestEvaluateOnObjectValidationEvalErrorSetsErr guards that an eval failure of
// the validation expression itself becomes Err (unknown verdict), not a pass.
func TestEvaluateOnObjectValidationEvalErrorSetsErr(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{{Expression: "object.spec.thisKeyDoesNotExist.value == 1"}}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Error(t, results[0].Err)
	assert.False(t, results[0].Passed)
}

// TestEvaluateOnObjectVariableErrorIsTopLevel guards that a variable that fails
// to evaluate aborts the whole object with a top-level error rather than
// producing untrustworthy verdicts.
func TestEvaluateOnObjectVariableErrorIsTopLevel(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	variables := []Variable{
		{Name: "broken", Expression: "object.spec.thisKeyDoesNotExist.value"},
	}
	validations := []Validation{{Expression: "true"}}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, variables, validations)
	require.Error(t, err)
	assert.Nil(t, results)
}

func TestEvaluateOnObjectResultsAreOneToOne(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{
		{Expression: "object.spec.hostNetwork == false"},
		{Expression: "object.metadata.name == 'nginx'"},
		{Expression: "object.metadata.namespace == 'production'"},
	}

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.False(t, results[0].Passed)
	assert.True(t, results[1].Passed)
	assert.True(t, results[2].Passed)
}
