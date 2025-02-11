package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The function should return a non-nil pointer.
func TestNewKubescape_ReturnsNonNilPointer(t *testing.T) {
	ctx := context.TODO()
	k := NewKubescape(ctx)
	assert.NotNil(t, k)
}

// The function should not panic.
func TestNewKubescape_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Function panicked: %v", r)
		}
	}()
	ctx := context.TODO()
	NewKubescape(ctx)
}
