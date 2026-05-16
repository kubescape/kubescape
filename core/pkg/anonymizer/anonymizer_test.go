package anonymizer

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
)

func TestApply(t *testing.T) {
	tests := []struct {
		name    string
		handler *resultshandling.ResultsHandler
	}{
		{
			name:    "nil handler should return without error",
			handler: nil,
		},
		{
			name:    "nil scan data should return without error",
			handler: &resultshandling.ResultsHandler{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				err := Apply(test.handler)
				assert.NoError(t, err)
			})
		})
	}
}
