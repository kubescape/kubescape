package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A ValidatingAdmissionPolicy's `message` is emitted verbatim; only
// `messageExpression` is evaluated by CEL. C-0013, C-0198 and C-0210 used to
// put a CEL string concatenation in `message`, so a violation on any of them
// showed the literal, unevaluated expression instead of a message naming the
// resource (see the messageExpression fix in this file's sibling changes).
//
// TestNoEvalErrorOnMinimalWorkloads in optionalfields_test.go exists
// specifically because a `make sync-vap` from a release that predates a
// hand-applied fix silently reverts it while the rest of the suite stays
// green. The two tests below are the same guard for this fix: nothing else
// evaluates `message`, so a regression here would otherwise only surface as a
// user staring at raw CEL source in a scan report.

// TestNoStaticMessageIsACELExpression sweeps every validation's `message` for
// a stray CEL expression. "object." is not something a hand-written message
// would ever contain, so its presence means a CEL expression landed in the
// wrong field.
func TestNoStaticMessageIsACELExpression(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	for name, vap := range catalog.byName {
		for i, v := range vap.Validations {
			assert.NotContainsf(t, v.Message, "object.",
				"%s validation[%d] puts a CEL expression in `message`, which is emitted verbatim; use messageExpression instead", name, i)
		}
	}
}

// TestEveryMessageExpressionCompiles is the other half: a messageExpression
// that fails to compile does not fail a scan either. resolveMessage falls
// back to Message, then a default, so a broken expression - a typo, or one
// referencing a variable that no longer exists - would only ever be caught
// here, not by any real evaluation.
func TestEveryMessageExpressionCompiles(t *testing.T) {
	env, err := NewEnv()
	require.NoError(t, err)

	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	for name, vap := range catalog.byName {
		for i, v := range vap.Validations {
			if v.MessageExpression == "" {
				continue
			}
			_, issues := env.Compile(inlineVariables(v.MessageExpression, vap.Variables))
			assert.NoErrorf(t, issues.Err(),
				"%s validation[%d] messageExpression does not compile", name, i)
		}
	}
}
