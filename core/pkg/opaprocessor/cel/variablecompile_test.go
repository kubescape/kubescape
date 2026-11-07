package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A validation that reads a variable which does not compile must come out the
// same as a validation that does not compile itself: an unknown verdict, not a
// failurePolicy deny.
func TestVariableCompileErrorIsNotAnExpressionError(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	fail := admissionregistrationv1.Fail
	results, err := e.EvaluateOnObject(context.Background(), cycleTestObject(), nil, nil,
		[]Variable{{Name: "bad", Expression: "object.spec.("}, {Name: "good", Expression: "object.spec.replicas"}},
		[]Validation{
			{Expression: "variables.bad == 1"},
			{Expression: "object.spec.("},
			{Expression: "variables.good == 3"},
			{Expression: "object.spec.missing == 1"},
		},
		&fail,
	)
	require.NoError(t, err)
	require.Len(t, results, 4)

	require.Error(t, results[0].Err)
	assert.Contains(t, results[0].Err.Error(), `variable "bad"`)
	assert.False(t, IsExpressionError(results[0].Err), "variable compile error: %v", results[0].Err)
	require.Error(t, results[1].Err)
	assert.False(t, IsExpressionError(results[1].Err), "validation compile error: %v", results[1].Err)

	assert.True(t, results[2].Passed, "a variable that compiles is unaffected")
	require.Error(t, results[3].Err)
	assert.True(t, IsExpressionError(results[3].Err), "a real eval error is still an expression error")
}

// The same goes for a matchCondition that reads the broken variable: the gate
// answers exactly as it does for a condition that does not compile.
func TestMatchConditionReadingUncompiledVariable(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	policy := func(condition string) *VAP {
		return newVAP(&admissionregistrationv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "broken-variable"},
			Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
				Variables:       []admissionregistrationv1.Variable{{Name: "bad", Expression: "object.spec.("}},
				MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "gate", Expression: condition}},
				Validations:     []admissionregistrationv1.Validation{{Expression: "true"}},
			},
		})
	}

	viaVariable, err := e.EvaluateVAPGate(context.Background(), policy("variables.bad == 1"), cycleTestObject(), nil)
	require.NoError(t, err)
	itself, err := e.EvaluateVAPGate(context.Background(), policy("object.spec.("), cycleTestObject(), nil)
	require.NoError(t, err)

	require.Len(t, viaVariable.Results, 1)
	require.Len(t, itself.Results, 1)
	assert.Equal(t, itself.Applicable, viaVariable.Applicable)
	assert.Equal(t, itself.FailOnError, viaVariable.FailOnError)
	assert.Contains(t, viaVariable.Results[0].Err.Error(), `variable "bad"`)
	assert.False(t, IsExpressionError(itself.Results[0].Err))
	assert.False(t, IsExpressionError(viaVariable.Results[0].Err))
}
