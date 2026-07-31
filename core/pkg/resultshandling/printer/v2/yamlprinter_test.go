package printer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewYamlPrinter(t *testing.T) {
	yp := NewYamlPrinter()
	assert.NotNil(t, yp)
}

func TestSetWriter_Yaml(t *testing.T) {
	yp := NewYamlPrinter()
	assert.NotNil(t, yp)

	// Test without outputFile (should use stdout)
	yp.SetWriter(context.TODO(), "")
	assert.NotNil(t, yp.writer)
	yp.CloseWriter()
}

func TestScore_Yaml(t *testing.T) {
	tests := []struct {
		name  string
		score float32
	}{
		{
			name:  "Score between 0 and 100",
			score: 21.0,
		},
		{
			name:  "Score less than 0",
			score: -20.0,
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
		},
		{
			name:  "Score 50",
			score: 50.0,
		},
		{
			name:  "Zero Score",
			score: 0.0,
		},
		{
			name:  "Perfect Score",
			score: 100,
		},
	}

	yp := NewYamlPrinter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yp.Score(tt.score)
		})
	}
}
