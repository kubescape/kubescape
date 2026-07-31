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
	assert.Equal(t, -3, Float64ToInt(-3.49))
	assert.Equal(t, -4, Float64ToInt(-3.5))
	assert.Equal(t, -4, Float64ToInt(-3.51))
}

func TestFloat32ToInt(t *testing.T) {
	assert.Equal(t, 3, Float32ToInt(3.49))
	assert.Equal(t, 4, Float32ToInt(3.5))
	assert.Equal(t, 4, Float32ToInt(3.51))
	assert.Equal(t, 0, Float32ToInt(0.0))
	assert.Equal(t, -3, Float32ToInt(-3.49))
	assert.Equal(t, -4, Float32ToInt(-3.5))
	assert.Equal(t, -4, Float32ToInt(-3.51))
}

func TestFloat16ToInt(t *testing.T) {
	assert.Equal(t, 3, Float16ToInt(3.49))
	assert.Equal(t, 4, Float16ToInt(3.5))
	assert.Equal(t, 4, Float16ToInt(3.51))
	assert.Equal(t, 0, Float16ToInt(0.0))
	assert.Equal(t, -3, Float16ToInt(-3.49))
	assert.Equal(t, -4, Float16ToInt(-3.5))
	assert.Equal(t, -4, Float16ToInt(-3.51))
}

func TestFloat32ToIntComplianceScore(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  int
	}{
		{name: "perfect score stays 100", score: 100.0, want: 100},
		{name: "99.5 does not round up to 100", score: 99.5, want: 99},
		{name: "99.9 does not round up to 100", score: 99.9, want: 99},
		{name: "99.0 stays 99", score: 99.0, want: 99},
		{name: "50.4 rounds normally", score: 50.4, want: 50},
		{name: "0.4 rounds normally", score: 0.4, want: 0},
		{name: "0.0 stays 0", score: 0.0, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Float32ToIntComplianceScore(tt.score))
		})
	}
}
