package printer

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/stretchr/testify/assert"
)

// Compile-time check: SilentPrinter must satisfy IPrinter.
var _ printer.IPrinter = &SilentPrinter{}

func TestSilentPrinter_PrintNextSteps(t *testing.T) {
	sp := &SilentPrinter{}
	assert.NotPanics(t, func() {
		sp.PrintNextSteps()
	}, "PrintNextSteps should be a no-op and never panic")
}

func TestSilentPrinter_ActionPrint(t *testing.T) {
	sp := &SilentPrinter{}
	assert.NotPanics(t, func() {
		sp.ActionPrint(context.Background(), nil, nil)
	}, "ActionPrint should be a no-op and never panic")
}

func TestSilentPrinter_SetWriter(t *testing.T) {
	sp := &SilentPrinter{}
	tests := []struct {
		name       string
		outputFile string
	}{
		{name: "empty path", outputFile: ""},
		{name: "file path", outputFile: "/tmp/output.json"},
		{name: "relative path", outputFile: "./results.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				sp.SetWriter(context.Background(), tt.outputFile)
			}, "SetWriter should be a no-op and never panic")
		})
	}
}

func TestSilentPrinter_Score(t *testing.T) {
	sp := &SilentPrinter{}
	scores := []struct {
		name  string
		score float32
	}{
		{name: "zero", score: 0},
		{name: "full", score: 100},
		{name: "partial", score: 67.5},
		{name: "negative", score: -1},
	}
	for _, tt := range scores {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				sp.Score(tt.score)
			}, "Score should be a no-op and never panic")
		})
	}
}
