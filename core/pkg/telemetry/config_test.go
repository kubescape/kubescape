package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearEndpointEnvironment isolates a test from a developer or CI environment
// that already points at a collector, which would otherwise flip Enabled().
func clearEndpointEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{EnvEndpoint, EnvTracesEndpoint, EnvMetricsEndpoint} {
		t.Setenv(name, "")
	}
}

func TestResolveConfigDisabledWithoutEndpoint(t *testing.T) {
	clearEndpointEnvironment(t)

	cfg, err := ResolveConfig("", "v3.0.0")

	require.NoError(t, err)
	assert.False(t, cfg.Enabled())
	assert.Empty(t, cfg.Endpoint)
	assert.False(t, cfg.FromEnvironment)
}

func TestResolveConfigEndpointForms(t *testing.T) {
	clearEndpointEnvironment(t)

	tests := []struct {
		name         string
		endpoint     string
		wantEndpoint string
		wantInsecure bool
	}{
		{
			name:         "host and port is treated as plaintext",
			endpoint:     "localhost:4317",
			wantEndpoint: "localhost:4317",
			wantInsecure: true,
		},
		{
			name:         "http url is plaintext",
			endpoint:     "http://collector.example.com:4318",
			wantEndpoint: "collector.example.com:4318",
			wantInsecure: true,
		},
		{
			name:         "https url requires tls",
			endpoint:     "https://collector.example.com:4318",
			wantEndpoint: "collector.example.com:4318",
			wantInsecure: false,
		},
		{
			name:         "bracketed ipv6 authority",
			endpoint:     "[::1]:4317",
			wantEndpoint: "[::1]:4317",
			wantInsecure: true,
		},
		{
			name:         "ipv6 url",
			endpoint:     "http://[::1]:4318",
			wantEndpoint: "[::1]:4318",
			wantInsecure: true,
		},
		{
			name:         "surrounding whitespace is ignored",
			endpoint:     "  localhost:4317  ",
			wantEndpoint: "localhost:4317",
			wantInsecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ResolveConfig(tt.endpoint, "v3.0.0")

			require.NoError(t, err)
			assert.True(t, cfg.Enabled())
			assert.Equal(t, tt.wantEndpoint, cfg.Endpoint)
			assert.Equal(t, tt.wantInsecure, cfg.Insecure)
			assert.Equal(t, ProtocolGRPC, cfg.Protocol)
			assert.Equal(t, DefaultServiceName, cfg.ServiceName)
			assert.Equal(t, "v3.0.0", cfg.Version)
		})
	}
}

func TestResolveConfigRejectsMalformedEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "missing port", endpoint: "localhost"},
		{name: "non numeric port", endpoint: "localhost:grpc"},
		{name: "path without scheme", endpoint: "localhost:4317/v1/traces"},
		{name: "unsupported scheme", endpoint: "grpc://localhost:4317"},
		{name: "missing host", endpoint: "http://"},
		{name: "port only", endpoint: ":4317"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveConfig(tt.endpoint, "")

			require.Error(t, err)
			assert.Contains(t, err.Error(), "--otel-endpoint")
		})
	}
}

func TestResolveConfigInsecureEnvOverridesScheme(t *testing.T) {
	t.Setenv(EnvInsecure, "false")

	cfg, err := ResolveConfig("localhost:4317", "")

	require.NoError(t, err)
	assert.False(t, cfg.Insecure)
}

func TestResolveConfigIgnoresUnparsableInsecureEnv(t *testing.T) {
	t.Setenv(EnvInsecure, "definitely-not-a-bool")

	cfg, err := ResolveConfig("localhost:4317", "")

	require.NoError(t, err)
	assert.True(t, cfg.Insecure)
}

func TestResolveConfigEnablesFromEnvironment(t *testing.T) {
	for _, name := range []string{EnvEndpoint, EnvTracesEndpoint, EnvMetricsEndpoint} {
		t.Run(name, func(t *testing.T) {
			clearEndpointEnvironment(t)
			t.Setenv(name, "http://localhost:4318")

			cfg, err := ResolveConfig("", "")

			require.NoError(t, err)
			assert.True(t, cfg.Enabled())
			assert.True(t, cfg.FromEnvironment)
			// The exporters read the variables themselves, so nothing is pinned here.
			assert.Empty(t, cfg.Endpoint)
		})
	}
}

func TestResolveConfigFlagWinsOverEnvironment(t *testing.T) {
	t.Setenv(EnvEndpoint, "http://from-env:4318")

	cfg, err := ResolveConfig("from-flag:4317", "")

	require.NoError(t, err)
	assert.Equal(t, "from-flag:4317", cfg.Endpoint)
	assert.False(t, cfg.FromEnvironment)
}

func TestResolveConfigProtocol(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "default", value: "", want: ProtocolGRPC},
		{name: "grpc", value: ProtocolGRPC, want: ProtocolGRPC},
		{name: "http protobuf", value: ProtocolHTTP, want: ProtocolHTTP},
		{name: "http alias", value: "http", want: ProtocolHTTP},
		{name: "json is unsupported", value: "http/json", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != "" {
				t.Setenv(EnvProtocol, tt.value)
			}

			cfg, err := ResolveConfig("localhost:4317", "")

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.Protocol)
		})
	}
}

func TestResolveConfigServiceNameFromEnvironment(t *testing.T) {
	t.Setenv(EnvServiceName, "kubescape-ci")

	cfg, err := ResolveConfig("localhost:4317", "")

	require.NoError(t, err)
	assert.Equal(t, "kubescape-ci", cfg.ServiceName)
}
