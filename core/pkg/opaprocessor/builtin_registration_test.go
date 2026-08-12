package opaprocessor

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

// TestRegisterOPABuiltins_OnlyRegistersOncePerProcess guards against a
// regression where the sync.Once guarding rego.RegisterBuiltin1/2 lived on
// OPAProcessor as a struct field instead of at package level. Because
// RegisterBuiltin mutates OPA's process-global ast.Builtins/ast.BuiltinMap, a
// per-instance Once gave every new OPAProcessor (i.e. every scan) its own,
// never-fired Once, so the registration ran again on every scan: unbounded
// growth of ast.Builtins for the life of a long-running process (httphandler,
// MCP server), and one concurrency change away from the "concurrent map
// read/write panic" OPA's own docs warn RegisterBuiltin can cause after
// initialization.
func TestRegisterOPABuiltins_OnlyRegistersOncePerProcess(t *testing.T) {
	// Establish the baseline after at least one registration (init() already
	// triggered this before any test runs, but calling it again here keeps
	// the test correct even if that ever changes) so the assertion below is
	// independent of test ordering and doesn't hardcode the builtin count.
	registerOPABuiltins()
	countAfterFirst := len(ast.Builtins)

	// Simulate what used to happen once per scan: registerOPABuiltins is
	// invoked repeatedly, as if from several independent OPAProcessor
	// instances/runRegoOnK8s calls across the life of a long-running process.
	for i := 0; i < 5; i++ {
		registerOPABuiltins()
	}

	assert.Equal(t, countAfterFirst, len(ast.Builtins),
		"registerOPABuiltins must not add builtins after the first call")

	assert.NotNil(t, ast.BuiltinMap[cosignVerifySignatureDeclaration.Name], "cosign.verify must be registered")
	assert.NotNil(t, ast.BuiltinMap[cosignHasSignatureDeclaration.Name], "cosign.has_signature must be registered")
	assert.NotNil(t, ast.BuiltinMap[imageNameNormalizeDeclaration.Name], "image.parse_normalized_name must be registered")
}
