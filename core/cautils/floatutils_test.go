package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFloat64ToInt(t *testing.T) {
	assert.Equal(t, 3, Float64ToInt(3.49))
	assert.Equal(t, 4, Float64ToInt(3.5))
	assert.Equal(t, 4, Float64ToInt(3.51))
}

func TestFloat32ToInt(t *testing.T) {
	assert.Equal(t, 3, Float32ToInt(3.49))
	assert.Equal(t, 4, Float32ToInt(3.5))
	assert.Equal(t, 4, Float32ToInt(3.51))
}
func TestFloat16ToInt(t *testing.T) {
	assert.Equal(t, 3, Float16ToInt(3.49))
	assert.Equal(t, 4, Float16ToInt(3.5))
	assert.Equal(t, 4, Float16ToInt(3.51))
}
