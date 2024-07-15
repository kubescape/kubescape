package resourcehandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Initializes a new instance of FileResourceHandler.
func TestNewFileResourceHandler_InitializesNewInstance(t *testing.T) {
	fileHandler := NewFileResourceHandler()
	assert.NotNil(t, fileHandler)
}
