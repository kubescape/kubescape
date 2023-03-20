package cautils

import (
	"testing"

	"github.com/kubescape/go-logger"
)

func TestStartSpinner(t *testing.T) {
	tests := []struct {
		name        string
		loggerLevel string
		enabled     bool
	}{
		{
			name:        "TestStartSpinner - disabled",
			loggerLevel: "warning",
			enabled:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.L().SetLevel(tt.loggerLevel)
			StartSpinner()
			if !tt.enabled {
				if spinner != nil {
					t.Errorf("spinner should be nil")
				}
			}
		})
	}
}
