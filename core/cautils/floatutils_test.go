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

func TestComplianceScoreToInt(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  int
	}{
		{
			name:  "ordinary fractional score still rounds",
			score: 20.7,
			want:  21,
		},
		{
			name:  "almost perfect score does not round to perfect",
			score: 99.5,
			want:  99,
		},
		{
			name:  "near-perfect score does not round to perfect",
			score: 99.99,
			want:  99,
		},
		{
			name:  "perfect score remains perfect",
			score: 100,
			want:  100,
		},
		{
			name:  "unscored sentinel remains negative",
			score: -1,
			want:  -1,
		},
		{
			name:  "integer score from 53 of 100 avoids float32 underflow",
			score: (float32(53) / float32(100)) * 100,
			want:  53,
		},
		{
			name:  "integer score from 59 of 100 avoids float32 underflow",
			score: (float32(59) / float32(100)) * 100,
			want:  59,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ComplianceScoreToInt(tt.score))
		})
	}
}

func TestComplianceScoreToString(t *testing.T) {
	tests := []struct {
		name      string
		score     float32
		precision int
		want      string
	}{
		{
			name:      "ordinary score formats with requested precision",
			score:     95.4321,
			precision: 2,
			want:      "95.43",
		},
		{
			name:      "score above 99.995 does not round to 100.00",
			score:     99.996,
			precision: 2,
			want:      "99.99",
		},
		{
			name:      "score exactly 99.99 stays 99.99",
			score:     99.99,
			precision: 2,
			want:      "99.99",
		},
		{
			name:      "perfect score 100 remains 100.00",
			score:     100.0,
			precision: 2,
			want:      "100.00",
		},
		{
			name:      "score near 100 with precision 1 does not round to 100.0",
			score:     99.96,
			precision: 1,
			want:      "99.9",
		},
		{
			name:      "zero score formats properly",
			score:     0.0,
			precision: 2,
			want:      "0.00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ComplianceScoreToString(tt.score, tt.precision))
		})
	}
}

func TestRiskScoreToInt(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  int
	}{
		{
			name:  "ordinary fractional score still rounds",
			score: 20.4,
			want:  20,
		},
		{
			name:  "ordinary fractional score rounds up",
			score: 20.7,
			want:  21,
		},
		{
			name:  "small non-zero risk score does not round to zero",
			score: 0.4,
			want:  1,
		},
		{
			name:  "tiny non-zero risk score does not round to zero",
			score: 0.01,
			want:  1,
		},
		{
			name:  "zero risk score remains zero",
			score: 0.0,
			want:  0,
		},
		{
			name:  "unscored sentinel remains negative",
			score: -1.0,
			want:  -1,
		},
		{
			name:  "high risk score rounds normally",
			score: 99.6,
			want:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RiskScoreToInt(tt.score))
		})
	}
}

func TestFloat32ToIntFloor(t *testing.T) {
	assert.Equal(t, 99, Float32ToIntFloor(99.5))
	assert.Equal(t, 99, Float32ToIntFloor(99.9))
	assert.Equal(t, 100, Float32ToIntFloor(100.0))
	assert.Equal(t, 0, Float32ToIntFloor(0.5))
	// boundary: inside epsilon snaps to integer
	assert.Equal(t, 100, Float32ToIntFloor(100-float32(5e-5)))
	// boundary: outside epsilon still floors
	assert.Equal(t, 99, Float32ToIntFloor(100-float32(2e-3)))
	// negative values preserve standard floor semantics
	assert.Equal(t, -1, Float32ToIntFloor(-1e-5))
	assert.Equal(t, -2, Float32ToIntFloor(-1.00005))
	assert.Equal(t, -1, Float32ToIntFloor(-0.5))
}

func TestFloat32ToIntFloor_Float32Precision(t *testing.T) {
	assert.Equal(t, 53, Float32ToIntFloor(float32(53)/float32(100)*100))
	assert.Equal(t, 59, Float32ToIntFloor(float32(59)/float32(100)*100))
	assert.Equal(t, 53, Float32ToIntFloor(float32(106)/float32(200)*100))
}
