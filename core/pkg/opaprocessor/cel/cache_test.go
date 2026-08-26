package cel

import (
	"context"
	"errors"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProgramCacheCompilesOnce proves the second lookup of an expression is
// served from the cache: the compile function runs exactly once no matter how
// many times the expression is fetched.
func TestProgramCacheCompilesOnce(t *testing.T) {
	env, err := newEnv()
	require.NoError(t, err)

	compiles := 0
	cache := newProgramCache(func(expr string) (cel.Program, error) {
		compiles++
		ast, issues := env.Compile(expr)
		require.NoError(t, issues.Err())
		return env.Program(ast)
	})

	first, err := cache.get("1 + 1 == 2")
	require.NoError(t, err)
	second, err := cache.get("1 + 1 == 2")
	require.NoError(t, err)

	assert.Equal(t, 1, compiles, "second lookup must not recompile")
	assert.Same(t, first, second, "both lookups must return the memoized program")

	_, err = cache.get("2 + 2 == 4")
	require.NoError(t, err)
	assert.Equal(t, 2, compiles, "a different expression is a different cache entry")
}

// TestProgramCacheCachesCompileFailure proves a compile failure is memoized: a
// broken expression is broken against every object, so it must be attempted
// once and its error served afterwards, not recompiled per scanned object.
func TestProgramCacheCachesCompileFailure(t *testing.T) {
	compiles := 0
	compileErr := errors.New("compile: boom")
	cache := newProgramCache(func(expr string) (cel.Program, error) {
		compiles++
		return nil, compileErr
	})

	_, err := cache.get("this does not compile")
	require.ErrorIs(t, err, compileErr)
	_, err = cache.get("this does not compile")
	require.ErrorIs(t, err, compileErr, "the cached error must be served on later lookups")

	assert.Equal(t, 1, compiles, "a failing expression must be compiled only once")
}

// TestEvaluatorDoesNotCacheEvalErrors proves an eval error does not poison the
// cached program. Eval errors are data-specific — here the field is missing on
// the first object but present on the second — so the same expression must
// still produce a real verdict for the next object.
func TestEvaluatorDoesNotCacheEvalErrors(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{{Expression: "object.spec.hostNetwork == false"}}

	// No spec at all: the field access errors at eval time.
	broken := map[string]any{"kind": "Pod", "metadata": map[string]any{"name": "no-spec"}}
	results, err := e.EvaluateOnObject(context.Background(), broken, nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Error(t, results[0].Err)

	// Same expression, well-formed object: must get a clean verdict, proving the
	// earlier eval error was not memoized.
	good := map[string]any{
		"kind":     "Pod",
		"metadata": map[string]any{"name": "ok"},
		"spec":     map[string]any{"hostNetwork": false},
	}
	results, err = e.EvaluateOnObject(context.Background(), good, nil, nil, nil, validations)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Err)
	assert.True(t, results[0].Passed)
}

// TestEvaluatorReusesCachedProgram proves the Evaluator routes evaluation
// through the cache: after evaluating the same validation against two objects,
// the cache holds exactly one entry for the expression.
func TestEvaluatorReusesCachedProgram(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	validations := []Validation{{Expression: "object.spec.hostNetwork == false"}}

	for range 2 {
		results, err := e.EvaluateOnObject(context.Background(), hostNetworkPod(), nil, nil, nil, validations)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.False(t, results[0].Passed)
	}

	assert.Len(t, e.programs.entries, 1, "both evaluations must share one cache entry")
}
