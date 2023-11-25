package testutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrentDir(t *testing.T) {
	currDir := CurrentDir()
	assert.NotNil(t, currDir)
	assert.Contains(t, currDir, "kubescape/internal/testutils")
}
