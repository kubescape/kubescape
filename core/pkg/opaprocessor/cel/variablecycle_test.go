package cel

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// None of these tests may reach unbounded recursion: a Go stack overflow is a
// fatal error that takes the whole test binary down, so a regression here shows
// up as a crashed run rather than a failed assertion. That is why every cyclic
// case goes through the guard and none through a child process.

func cycleTestObject() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "prod"},
		"spec":       map[string]any{"hostNetwork": false, "replicas": int64(3)},
	}
}

func evalVars(t *testing.T, vars []Variable, validations ...string) []ValidationResult {
	t.Helper()
	e, err := NewEvaluator()
	require.NoError(t, err)
	vs := make([]Validation, 0, len(validations))
	for _, expr := range validations {
		vs = append(vs, Validation{Expression: expr})
	}
	results, err := e.EvaluateOnObject(context.Background(), cycleTestObject(), nil, nil, vars, vs)
	require.NoError(t, err)
	require.Len(t, results, len(validations))
	return results
}

func TestVariableCycleIsReportedNotRecursed(t *testing.T) {
	tests := []struct {
		name       string
		vars       []Variable
		validation string
		wantCycle  string
	}{
		{
			name:       "direct self reference",
			vars:       []Variable{{"a", "variables.a + 1"}},
			validation: "variables.a == 1",
			wantCycle:  "a -> a",
		},
		{
			name:       "two variables referencing each other",
			vars:       []Variable{{"a", "variables.b"}, {"b", "variables.a"}},
			validation: "variables.a == 1",
			wantCycle:  "a -> b -> a",
		},
		{
			name:       "three variable cycle",
			vars:       []Variable{{"a", "variables.b"}, {"b", "variables.c"}, {"c", "variables.a"}},
			validation: "variables.a == 1",
			wantCycle:  "a -> b -> c -> a",
		},
		{
			name:       "cycle is reported from wherever it is entered",
			vars:       []Variable{{"a", "variables.b"}, {"b", "variables.c"}, {"c", "variables.a"}},
			validation: "variables.b == 1",
			wantCycle:  "b -> c -> a -> b",
		},
		{
			name:       "entry variable outside the cycle is not part of it",
			vars:       []Variable{{"entry", "variables.a"}, {"a", "variables.b"}, {"b", "variables.a"}},
			validation: "variables.entry == 1",
			wantCycle:  "a -> b -> a",
		},
		{
			name:       "cycle through a bracket index",
			vars:       []Variable{{"a", `variables["b"]`}, {"b", `variables["a"]`}},
			validation: "variables.a == 1",
			wantCycle:  "a -> b -> a",
		},
		{
			name:       "cycle through a comprehension",
			vars:       []Variable{{"a", "[1, 2].map(i, variables.a)"}},
			validation: "size(variables.a) == 2",
			wantCycle:  "a -> a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := evalVars(t, tt.vars, tt.validation)[0]
			require.Error(t, res.Err)
			assert.False(t, res.Passed, "a cycle must never read as a pass")
			assert.Contains(t, res.Err.Error(), "cyclic reference "+tt.wantCycle)
			assert.True(t, IsExpressionError(res.Err), "same classification as any other variable error")
		})
	}
}

func TestVariableCycleErrorIsDeterministic(t *testing.T) {
	vars := []Variable{{"a", "variables.b"}, {"b", "variables.a"}}
	first := evalVars(t, vars, "variables.a == 1")[0].Err
	require.Error(t, first)
	for range 5 {
		assert.Equal(t, first.Error(), evalVars(t, vars, "variables.a == 1")[0].Err.Error())
	}
}

func TestValidVariableDependencies(t *testing.T) {
	tests := []struct {
		name        string
		vars        []Variable
		validations []string
		want        []bool
	}{
		{
			name:        "single variable",
			vars:        []Variable{{"a", "1"}},
			validations: []string{"variables.a == 1"},
			want:        []bool{true},
		},
		{
			name:        "multi-level chain",
			vars:        []Variable{{"a", "1"}, {"b", "variables.a + 1"}, {"c", "variables.b + 1"}},
			validations: []string{"variables.c == 3", "variables.c == 4"},
			want:        []bool{true, false},
		},
		{
			name:        "forward reference without a cycle still resolves",
			vars:        []Variable{{"a", "variables.b + 1"}, {"b", "1"}},
			validations: []string{"variables.a == 2"},
			want:        []bool{true},
		},
		{
			name:        "longer forward chain",
			vars:        []Variable{{"a", "variables.b + 1"}, {"b", "variables.c + 1"}, {"c", "1"}},
			validations: []string{"variables.a == 3"},
			want:        []bool{true},
		},
		{
			name:        "diamond: a shared dependency is not a cycle",
			vars:        []Variable{{"a", "1"}, {"b", "variables.a + 1"}, {"c", "variables.a + 2"}, {"d", "variables.b + variables.c"}},
			validations: []string{"variables.d == 5"},
			want:        []bool{true},
		},
		{
			name:        "one variable shared by several validations",
			vars:        []Variable{{"a", "object.spec.replicas"}},
			validations: []string{"variables.a == 3", "variables.a > 1", "variables.a < 3"},
			want:        []bool{true, true, false},
		},
		{
			name:        "independent variables",
			vars:        []Variable{{"a", "1"}, {"b", "2"}},
			validations: []string{"variables.a + variables.b == 3"},
			want:        []bool{true},
		},
		{
			name:        "unused variables are never evaluated",
			vars:        []Variable{{"a", "1"}, {"unused", "1/0"}},
			validations: []string{"variables.a == 1"},
			want:        []bool{true},
		},
		{
			name:        "the same variable read twice in one expression",
			vars:        []Variable{{"a", "2"}},
			validations: []string{"variables.a * variables.a == 4"},
			want:        []bool{true},
		},
		{
			name: "text that only resembles a variable reference",
			vars: []Variable{{"a", "object.spec.replicas"}, {"b", `"variables.b" + "variables.a"`}},
			validations: []string{
				`variables.b == "variables.bvariables.a"`,
				`object.metadata.name != "variables.a"`,
				`variables.a == 3`,
			},
			want: []bool{true, true, true},
		},
		{
			name:        "variable named like a field it reads",
			vars:        []Variable{{"replicas", "object.spec.replicas"}},
			validations: []string{"variables.replicas == 3"},
			want:        []bool{true},
		},
		{
			name:        "dyn(variables) still resolves",
			vars:        []Variable{{"a", "1"}},
			validations: []string{"dyn(variables).a == 1"},
			want:        []bool{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := evalVars(t, tt.vars, tt.validations...)
			for i, res := range results {
				require.NoErrorf(t, res.Err, "validation %d: %s", i, tt.validations[i])
				assert.Equalf(t, tt.want[i], res.Passed, "validation %d: %s", i, tt.validations[i])
			}
		})
	}
}

// A cycle nothing reads never runs, and one validation tripping a cycle must
// not disturb the validations that do not.
func TestVariableCycleOnlyAffectsWhatReadsIt(t *testing.T) {
	vars := []Variable{
		{"ok", "object.spec.replicas"},
		{"a", "variables.b"}, {"b", "variables.a"},
		{"self", "variables.self"},
	}

	t.Run("an unread cycle is not reported", func(t *testing.T) {
		res := evalVars(t, vars, "variables.ok == 3")[0]
		require.NoError(t, res.Err)
		assert.True(t, res.Passed)
	})

	t.Run("a cycle beside valid variables only fails its reader", func(t *testing.T) {
		results := evalVars(t, vars,
			"variables.ok == 3",
			"variables.a == 1",
			"variables.ok == 3",
			"variables.self == 1",
			"variables.ok > 100",
		)
		require.NoError(t, results[0].Err)
		assert.True(t, results[0].Passed)
		require.Error(t, results[1].Err)
		require.NoError(t, results[2].Err, "a failed cycle must leave no state behind for the next validation")
		assert.True(t, results[2].Passed)
		require.Error(t, results[3].Err)
		assert.Contains(t, results[3].Err.Error(), "cyclic reference self -> self")
		require.NoError(t, results[4].Err)
		assert.False(t, results[4].Passed, "a plain violation after a cycle is still a violation")
	})

	t.Run("re-reading a failed cycle keeps failing instead of looping", func(t *testing.T) {
		results := evalVars(t, vars, "variables.a == 1", "variables.a == 1", "variables.b == 1")
		for _, res := range results {
			require.Error(t, res.Err)
			assert.Contains(t, res.Err.Error(), "cyclic reference")
		}
	})

	t.Run("a variable that fails for another reason is not called a cycle", func(t *testing.T) {
		results := evalVars(t, []Variable{{"a", "variables.b"}, {"b", "1/0"}, {"c", "variables.missing"}, {"d", "1 +"}},
			"variables.a == 1", "variables.c == 1", "variables.d == 1")
		for i, res := range results {
			require.Errorf(t, res.Err, "validation %d", i)
			assert.NotContainsf(t, res.Err.Error(), "cyclic", "validation %d", i)
		}
	})

	t.Run("a failed evaluation leaves nothing behind for the next one", func(t *testing.T) {
		e, err := NewEvaluator()
		require.NoError(t, err)
		ctx := context.Background()
		cyclic := []Variable{{"a", "variables.b"}, {"b", "variables.a"}}
		valid := []Variable{{"a", "1"}, {"b", "variables.a + 1"}}
		val := []Validation{{Expression: "variables.b == 2"}}

		for range 3 {
			bad, err := e.EvaluateOnObject(ctx, cycleTestObject(), nil, nil, cyclic, val)
			require.NoError(t, err)
			require.Error(t, bad[0].Err)

			good, err := e.EvaluateOnObject(ctx, cycleTestObject(), nil, nil, valid, val)
			require.NoError(t, err)
			require.NoError(t, good[0].Err)
			assert.True(t, good[0].Passed)
		}
	})
}

// Violation paths and messages re-evaluate against the same variables, so a
// cycle among them must not recurse there either.
func TestVariableCycleDoesNotBreakPathsOrMessages(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	vars := []Variable{{"a", "variables.b"}, {"b", "variables.a"}, {"hn", "object.spec.hostNetwork"}}

	t.Run("a violation is still derived beside cyclic declarations", func(t *testing.T) {
		obj := cycleTestObject()
		obj["spec"].(map[string]any)["hostNetwork"] = true
		res, err := e.EvaluateOnObject(context.Background(), obj, nil, nil, vars,
			[]Validation{{Expression: "variables.hn == false", Message: "no host network"}})
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		assert.False(t, res[0].Passed)
		assert.Equal(t, "no host network", res[0].Message)
	})

	t.Run("a messageExpression that hits a cycle falls back to the message", func(t *testing.T) {
		res, err := e.EvaluateOnObject(context.Background(), cycleTestObject(), nil, nil, vars,
			[]Validation{{Expression: "false", Message: "static", MessageExpression: "string(variables.a)"}})
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		assert.False(t, res[0].Passed)
		assert.Equal(t, "static", res[0].Message)
	})
}

func TestVariableCycleEvaluationsAreIndependent(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	cyclic := []Variable{{"a", "variables.b"}, {"b", "variables.a"}}
	valid := []Variable{{"a", "1"}, {"b", "variables.a + 1"}}
	val := []Validation{{Expression: "variables.b == 2"}}

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vars, wantErr := valid, false
			if i%2 == 0 {
				vars, wantErr = cyclic, true
			}
			res, err := e.EvaluateOnObject(context.Background(), cycleTestObject(), nil, nil, vars, val)
			switch {
			case err != nil:
				errs <- err.Error()
			case wantErr && res[0].Err == nil:
				errs <- "cyclic evaluation produced no error"
			case !wantErr && (res[0].Err != nil || !res[0].Passed):
				errs <- "valid evaluation was disturbed by a concurrent cycle"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// cyclicPolicy builds a policy the way the bundle loader does, so failurePolicy
// defaulting (nil means Fail) is exercised through newVAP instead of set by hand.
func cyclicPolicy(fp *admissionregistrationv1.FailurePolicyType) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cyclic"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: fp,
			Variables: []admissionregistrationv1.Variable{
				{Name: "a", Expression: "variables.b"},
				{Name: "b", Expression: "variables.a"},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "gate", Expression: "variables.a == 1"},
			},
			Validations: []admissionregistrationv1.Validation{
				{Expression: "variables.a == 1"},
			},
		},
	}
}

func TestVariableCycleFailurePolicy(t *testing.T) {
	fail, ignore := admissionregistrationv1.Fail, admissionregistrationv1.Ignore
	e, err := NewEvaluator()
	require.NoError(t, err)
	ctx := context.Background()

	for _, tt := range []struct {
		name string
		fp   *admissionregistrationv1.FailurePolicyType
		deny bool
	}{
		{"unset defaults to Fail", nil, true},
		{"explicit Fail", &fail, true},
		{"Ignore", &ignore, false},
	} {
		t.Run("validation: "+tt.name, func(t *testing.T) {
			policy := cyclicPolicy(tt.fp)
			policy.Spec.MatchConditions = nil
			vap := newVAP(policy)

			eval, err := e.EvaluateVAP(ctx, vap, cycleTestObject(), nil, nil)
			require.NoError(t, err)
			require.True(t, eval.Applicable)
			require.Len(t, eval.Results, 1)
			assert.Equal(t, tt.deny, eval.FailOnError)
			if tt.deny {
				require.Error(t, eval.Results[0].Err)
				assert.Contains(t, eval.Results[0].Err.Error(), "cyclic reference a -> b -> a")
				assert.False(t, eval.Results[0].Passed)
				return
			}
			// Ignore maps every expression error to a pass, as it does for any
			// other failing variable; the cycle gets no special treatment here.
			assert.NoError(t, eval.Results[0].Err)
			assert.True(t, eval.Results[0].Passed)
		})

		t.Run("matchCondition: "+tt.name, func(t *testing.T) {
			policy := cyclicPolicy(tt.fp)
			vap := newVAP(policy)

			// The gate is evaluated on its own and answers before any
			// validation runs, so its error is distinct from a validation's.
			gate, err := e.EvaluateVAPGate(ctx, vap, cycleTestObject(), nil)
			require.NoError(t, err)
			if !tt.deny {
				assert.False(t, gate.Applicable, "Ignore skips the policy")
				assert.Empty(t, gate.Results)
				return
			}
			assert.True(t, gate.Applicable)
			assert.True(t, gate.FailOnError)
			require.Len(t, gate.Results, 1)
			assert.Empty(t, gate.Results[0].Expression, "the gate is not a validation")
			require.Error(t, gate.Results[0].Err)
			assert.Contains(t, gate.Results[0].Err.Error(), `matchCondition "gate"`)
			assert.Contains(t, gate.Results[0].Err.Error(), "cyclic reference a -> b -> a")

			full, err := e.EvaluateVAP(ctx, vap, cycleTestObject(), nil, nil)
			require.NoError(t, err)
			assert.Equal(t, gate.Results[0].Err.Error(), full.Results[0].Err.Error(), "validations do not run behind a failed gate")
		})
	}
}

// A policy without a cycle must produce the same verdicts through the real
// loader path as before the guard existed.
func TestAcyclicPolicyThroughNewVAPUnchanged(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "acyclic"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			Variables: []admissionregistrationv1.Variable{
				{Name: "late", Expression: "variables.base + 1"},
				{Name: "base", Expression: "object.spec.replicas"},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "gate", Expression: "variables.base == 3"}},
			Validations: []admissionregistrationv1.Validation{
				{Expression: "variables.late == 4"},
				{Expression: "variables.late == 5", Message: "replicas"},
			},
		},
	}
	eval, err := e.EvaluateVAP(context.Background(), newVAP(policy), cycleTestObject(), nil, nil)
	require.NoError(t, err)
	require.True(t, eval.Applicable)
	require.Len(t, eval.Results, 2)
	assert.NoError(t, eval.Results[0].Err)
	assert.True(t, eval.Results[0].Passed)
	assert.NoError(t, eval.Results[1].Err)
	assert.False(t, eval.Results[1].Passed)
	assert.Equal(t, "replicas", eval.Results[1].Message)
}
