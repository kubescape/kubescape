package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMcpScanNamespace(t *testing.T) {
	tests := []struct {
		name      string
		arguments map[string]any
		want      string
	}{
		{name: "omitted", arguments: map[string]any{}, want: ""},
		{name: "null is the same as omitted", arguments: map[string]any{"namespace": nil}, want: ""},
		{name: "plain namespace", arguments: map[string]any{"namespace": "default"}, want: "default"},
		{name: "surrounding whitespace is trimmed", arguments: map[string]any{"namespace": " default "}, want: "default"},
		{name: "star is cluster-wide", arguments: map[string]any{"namespace": "*"}, want: ""},
		{name: "padded star is cluster-wide", arguments: map[string]any{"namespace": " * "}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mcpScanNamespace(tt.arguments)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// The scan tools must agree with the tools that read namespace
			// through mcpStringArg on what counts as "no namespace".
			viaStringArg, toolErr := mcpStringArg(tt.arguments, "namespace")
			require.Nil(t, toolErr)
			if viaStringArg == "*" {
				viaStringArg = ""
			}
			assert.Equal(t, viaStringArg, got)
		})
	}

	_, err := mcpScanNamespace(map[string]any{"namespace": 123})
	assert.EqualError(t, err, "namespace argument must be a string")
}
