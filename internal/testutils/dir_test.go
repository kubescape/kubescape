package testutils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrentDir(t *testing.T) {
	p := filepath.Join("kubescape", "internal", "testutils")
	currDir := CurrentDir()
	assert.NotNil(t, currDir)
	assert.Contains(t, currDir, p)
}
