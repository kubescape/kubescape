package mcpserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMCPOptions(t *testing.T) {
	tests := []struct {
		name          string
		transport     string
		port          int
		wantTransport string
		wantErr       string
	}{
		{
			name:          "valid stdio",
			transport:     "stdio",
			port:          8080,
			wantTransport: "stdio",
		},
		{
			name:          "valid sse",
			transport:     "sse",
			port:          8080,
			wantTransport: "sse",
		},
		{
			name:          "uppercase sse normalized",
			transport:     "SSE",
			port:          8080,
			wantTransport: "sse",
		},
		{
			name:          "uppercase stdio with whitespace normalized",
			transport:     "  STDIO\t",
			port:          8080,
			wantTransport: "stdio",
		},
		{
			name:          "sse minimum port",
			transport:     "sse",
			port:          1,
			wantTransport: "sse",
		},
		{
			name:          "sse maximum port",
			transport:     "sse",
			port:          65535,
			wantTransport: "sse",
		},
		{
			name:      "unsupported transport",
			transport: "invalid",
			port:      8080,
			wantErr:   "unsupported transport 'invalid': must be 'sse' or 'stdio'",
		},
		{
			name:      "empty transport",
			transport: "",
			port:      8080,
			wantErr:   "unsupported transport '': must be 'sse' or 'stdio'",
		},
		{
			name:      "port zero",
			transport: "sse",
			port:      0,
			wantErr:   "invalid port 0: must be between 1 and 65535",
		},
		{
			name:      "negative port on sse",
			transport: "sse",
			port:      -1,
			wantErr:   "invalid port -1: must be between 1 and 65535",
		},
		{
			name:      "port exceeding maximum on sse",
			transport: "sse",
			port:      65536,
			wantErr:   "invalid port 65536: must be between 1 and 65535",
		},
		{
			name:      "negative port on stdio",
			transport: "stdio",
			port:      -1,
			wantErr:   "invalid port -1: must be between 1 and 65535",
		},
		{
			name:      "port exceeding maximum on stdio",
			transport: "stdio",
			port:      70000,
			wantErr:   "invalid port 70000: must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateMCPOptions(tt.transport, tt.port)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantTransport, got)
			}
		})
	}
}

func TestGetMCPServerCmd_ArgsValidation(t *testing.T) {
	cmd := GetMCPServerCmd()
	cmd.SetArgs([]string{"unexpected-arg"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command \"unexpected-arg\" for \"mcpserver\"")
}

func TestGetMCPServerCmd_FlagsValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "invalid transport rejected",
			args:    []string{"--transport", "websocket"},
			wantErr: "unsupported transport 'websocket': must be 'sse' or 'stdio'",
		},
		{
			name:    "negative port rejected",
			args:    []string{"--port", "-1"},
			wantErr: "invalid port -1: must be between 1 and 65535",
		},
		{
			name:    "port 0 rejected",
			args:    []string{"--port", "0"},
			wantErr: "invalid port 0: must be between 1 and 65535",
		},
		{
			name:    "port out of range rejected",
			args:    []string{"--port", "99999"},
			wantErr: "invalid port 99999: must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := GetMCPServerCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMCPServerEntrypoint_ValidatesEarly(t *testing.T) {
	ctx := context.Background()

	err := mcpServerEntrypoint(ctx, "invalid", 8080)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transport 'invalid': must be 'sse' or 'stdio'")

	err = mcpServerEntrypoint(ctx, "sse", -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port -1: must be between 1 and 65535")

	err = mcpServerEntrypoint(ctx, "sse", 70000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port 70000: must be between 1 and 65535")
}
