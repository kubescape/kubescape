package cel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateOnObjectJSONIntegers(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	// The JSON manifest reader preserves numbers as json.Number.
	decoder := json.NewDecoder(strings.NewReader(`{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": {"name": "integer-test", "namespace": "default"},
		"spec": {
			"replicas": 3, "low": 9007199254740992, "high": 9007199254740993,
			"max": 9223372036854775807, "min": -9223372036854775808,
			"unsigned": 18446744073709551615, "fraction": 1.5, "decimal": 3.0, "exponent": 3e0,
			"nested": [{"n": 9007199254740992}, {"n": 9007199254740993}]
		}
	}`))
	decoder.UseNumber()
	var obj map[string]any
	require.NoError(t, decoder.Decode(&obj))

	for _, expr := range []string{
		"object.spec.replicas + 1 == 4",
		"type(object.spec.replicas) == int",
		"object.spec.low != object.spec.high",
		"object.spec.high == 9007199254740993",
		"object.spec.max - 1 == 9223372036854775806",
		"object.spec.min + 1 == -9223372036854775807",
		"object.spec.unsigned == 18446744073709551615u",
		"object.spec.nested[0] != object.spec.nested[1]",
		"[{'n': 9007199254740992}, {'n': 9007199254740993}] == object.spec.nested",
		"object.spec.fraction + 0.5 == 2.0",
		"type(object.spec.decimal) == double && object.spec.decimal + 1.0 == 4.0",
		"type(object.spec.exponent) == double && object.spec.exponent + 1.0 == 4.0",
	} {
		t.Run(expr, func(t *testing.T) {
			results, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, nil, []Validation{{Expression: expr}})
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.NoError(t, results[0].Err)
			assert.True(t, results[0].Passed)
		})
	}
}

func TestControlConfigPreservesIntegerTypes(t *testing.T) {
	params, err := controlConfig()
	require.NoError(t, err)
	e, err := NewEvaluator()
	require.NoError(t, err)

	results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, params, nil, []Validation{
		{Expression: "type(params.settings.cpuLimitMax) == int && params.settings.cpuLimitMax + 1 == 6"},
		{Expression: "type(params.settings.cpuLimitMin) == double && params.settings.cpuLimitMin == 0.5"},
		{Expression: "params.settings.maxCriticalVulnerabilities.all(n, type(n) == int && n + 1 == 6)"},
	})
	require.NoError(t, err)
	require.Len(t, results, 3)
	for _, result := range results {
		assert.NoError(t, result.Err, result.Expression)
		assert.True(t, result.Passed, result.Expression)
	}
}

func TestJSONNumbersAcrossPolicyPhases(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	obj := hostNetworkPod()
	obj["spec"].(map[string]any)["containers"] = []any{
		map[string]any{"securityContext": map[string]any{"runAsUser": json.Number("2")}},
		map[string]any{"securityContext": map[string]any{"runAsUser": json.Number("8")}},
	}
	namespace := map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "production", "generation": json.Number("2")},
	}
	params := map[string]any{"limits": []any{json.Number("3")}}
	vap := &VAP{
		Variables: []Variable{{Name: "next", Expression: "object.spec.containers[0].securityContext.runAsUser + 1"}},
		matchConditions: []MatchCondition{{
			Name: "integer-gate", Expression: "variables.next == params.limits[0]",
		}},
		Validations: []Validation{
			{Expression: "namespaceObject.metadata.generation + 1 == variables.next"},
			{Expression: "params.limits.all(n, n + 1 == 4)"},
			{
				Expression:        "object.spec.containers.all(c, c.securityContext.runAsUser + 1 != 3)",
				MessageExpression: "'next=' + string(variables.next + 1)",
			},
		},
	}

	eval, err := e.EvaluateVAP(context.Background(), vap, obj, namespace, params)
	require.NoError(t, err)
	require.True(t, eval.Applicable)
	require.Len(t, eval.Results, 3)
	for _, result := range eval.Results {
		require.NoError(t, result.Err, result.Expression)
	}
	assert.True(t, eval.Results[0].Passed)
	assert.True(t, eval.Results[1].Passed)
	assert.False(t, eval.Results[2].Passed)
	assert.Equal(t, "next=4", eval.Results[2].Message)
	assert.Contains(t, eval.Results[2].Paths, PathHint{Path: "spec.containers[0].securityContext.runAsUser"})
	assert.Equal(t, []any{json.Number("3")}, params["limits"], "evaluation must not mutate the input")
}

func TestJSONNumberOverflowIsAnEvaluationError(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	for _, number := range []json.Number{"18446744073709551616", "-9223372036854775809", "1e309"} {
		t.Run(string(number), func(t *testing.T) {
			results, err := e.EvaluateOnObject(context.Background(), map[string]any{"number": number}, nil, nil, nil,
				[]Validation{{Expression: "object.number == object.number"}})
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Error(t, results[0].Err)
			assert.False(t, results[0].Passed)
		})
	}
}

func TestJSONNumberOverflowInAggregatesIsAnEvaluationError(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	obj := map[string]any{
		"left":      map[string]any{"n": json.Number("18446744073709551616")},
		"right":     map[string]any{"n": json.Number("18446744073709551617")},
		"leftList":  []any{json.Number("18446744073709551616")},
		"rightList": []any{json.Number("18446744073709551617")},
	}
	for _, expr := range []string{
		"object.left == object.right",
		"object.left != object.right",
		"object.leftList == object.rightList",
		"object.leftList != object.rightList",
		"object.left == {'n': 0}",
		"{'n': 0} == object.left",
		"object.leftList == [0]",
		"[0] == object.leftList",
		"[object.left.n] == [object.right.n]",
		"object.left in [object.right]",
		"[object.left] == [object.right]",
		"[object.?left] == [object.?right]",
		"{'v': object.?left.n} == {'v': object.?right.n}",
		"[object.?leftList] == [object.?rightList]",
	} {
		t.Run(expr, func(t *testing.T) {
			results, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, nil, []Validation{{Expression: expr}})
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Error(t, results[0].Err)
			assert.False(t, results[0].Passed)
		})
	}
}

func TestJSONNumberOverflowDoesNotAffectOtherBindings(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	obj := map[string]any{"allowed": true, "overflow": json.Number("18446744073709551616")}
	params := map[string]any{"allowed": true}
	results, err := e.EvaluateOnObject(context.Background(), obj, nil, params, nil, []Validation{
		{Expression: "params.allowed"},
		{Expression: "true || object.overflow == 0"},
		{Expression: "params.allowed || object.overflow == 0"},
	})
	require.NoError(t, err)
	require.Len(t, results, 3)
	for _, result := range results {
		assert.NoError(t, result.Err, result.Expression)
		assert.True(t, result.Passed, result.Expression)
	}
}
