package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEnvCompilesObjectExpression is the smallest possible proof that the
// env works: a literal expression referencing the declared "object" variable
// compiles with no error.
func TestNewEnvCompilesObjectExpression(t *testing.T) {
	env, err := newEnv()
	require.NoError(t, err)
	require.NotNil(t, env)

	_, issues := env.Compile(`object.metadata.name == "foo"`)
	assert.NoError(t, issues.Err())
}

// TestNewEnvRejectsAuthorizer documents, as an executable test, that authorizer
// is deliberately not declared: a policy referencing it must fail to compile
// rather than silently produce a wrong verdict.
func TestNewEnvRejectsAuthorizer(t *testing.T) {
	env, err := newEnv()
	require.NoError(t, err)

	_, issues := env.Compile(`authorizer.path("x").allowed()`)
	assert.Error(t, issues.Err())
}
