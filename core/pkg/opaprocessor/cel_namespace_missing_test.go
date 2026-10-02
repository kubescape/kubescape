package opaprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMissingNamespaceObjectOnlySkipsUnknownNamespacedInput(t *testing.T) {
	assert.True(t, missingNamespaceObject(true, "prod", nil))
	assert.False(t, missingNamespaceObject(false, "prod", nil), "policies that do not read the binding can still run")
	assert.False(t, missingNamespaceObject(true, "", nil), "cluster-scoped resources legitimately bind null")
	assert.False(t, missingNamespaceObject(true, "prod", map[string]any{"kind": "Namespace"}))
}
