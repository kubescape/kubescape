package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFloat64ToInt(t *testing.T) {
	assert.Equal(t, 3, Float64ToInt(3.49))
	assert.Equal(t, 4, Float64ToInt(3.5))
	assert.Equal(t, 4, Float64ToInt(3.51))
	assert.Equal(t, 0, Float64ToInt(0.0))
}

func TestFloat32ToInt(t *testing.T) {
	assert.Equal(t, 3, Float32ToInt(3.49))
	assert.Equal(t, 4, Float32ToInt(3.5))
	assert.Equal(t, 4, Float32ToInt(3.51))
	assert.Equal(t, 0, Float32ToInt(0.0))
}

func TestFloat32ToIntFloor(t *testing.T) {
	assert.Equal(t, 99, Float32ToIntFloor(99.5))
	assert.Equal(t, 99, Float32ToIntFloor(99.9))
	assert.Equal(t, 100, Float32ToIntFloor(100.0))
	assert.Equal(t, 0, Float32ToIntFloor(0.5))
}

func TestFloat32ToIntFloor_Float32Precision(t *testing.T) {
	assert.Equal(t, 53, Float32ToIntFloor(float32(53.0/100.0*100)))
	assert.Equal(t, 59, Float32ToIntFloor(float32(59.0/100.0*100)))
	assert.Equal(t, 53, Float32ToIntFloor(float32(106.0/200.0*100)))
}
