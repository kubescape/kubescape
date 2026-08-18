package imagescan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePlatform(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{
			name:  "empty keeps provider default",
			value: "",
			want:  "",
		},
		{
			name:  "whitespace-only keeps provider default",
			value: "  \t\n ",
			want:  "",
		},
		{
			name:  "canonical Linux amd64",
			value: "linux/amd64",
			want:  "linux/amd64",
		},
		{
			name:  "architecture-only defaults to Linux",
			value: "amd64",
			want:  "linux/amd64",
		},
		{
			name:  "common x86 alias is normalized",
			value: "linux/x86_64",
			want:  "linux/amd64",
		},
		{
			name:  "common ARM alias is normalized",
			value: "aarch64",
			want:  "linux/arm64",
		},
		{
			name:  "ARM variant is retained",
			value: "linux/arm/v7",
			want:  "linux/arm/v7",
		},
		{
			name:  "architecture and variant shorthand is retained",
			value: "arm/v7",
			want:  "linux/arm/v7",
		},
		{
			name:  "default ARM64 variant is normalized away",
			value: "linux/arm64/v8",
			want:  "linux/arm64",
		},
		{
			name:  "Windows platform is accepted",
			value: "windows/amd64",
			want:  "windows/amd64",
		},
		{
			name:  "surrounding whitespace is ignored",
			value: "  linux/arm64  ",
			want:  "linux/arm64",
		},
		{
			name:    "OS without architecture is rejected",
			value:   "linux",
			wantErr: "both operating system and architecture are required",
		},
		{
			name:    "unknown architecture is rejected",
			value:   "linux/toaster",
			wantErr: "invalid image platform",
		},
		{
			name:    "unknown operating system is rejected",
			value:   "toaster/amd64",
			wantErr: "invalid image platform",
		},
		{
			name:    "unknown OS cannot be reinterpreted as Linux with ARM variant",
			value:   "win/arm/v7",
			wantErr: "unknown operating system",
		},
		{
			name:    "unknown OS cannot be reinterpreted as Linux with amd64 variant",
			value:   "notanos/amd64/x",
			wantErr: "unknown operating system",
		},
		{
			name:    "three-component architecture shorthand requires an OS",
			value:   "arm/amd64/v7",
			wantErr: "operating system is required",
		},
		{
			name:    "wildcard is rejected",
			value:   "linux/*",
			wantErr: "wildcards not yet supported",
		},
		{
			name:    "extra component is rejected",
			value:   "linux/arm64/v8/extra",
			wantErr: "cannot parse platform specifier",
		},
		{
			name:    "empty component is rejected",
			value:   "linux//v8",
			wantErr: "invalid component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePlatform(tt.value)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProviderConfigCarriesPlatform(t *testing.T) {
	config := getProviderConfig(
		RegistryCredentials{Authority: "registry.example.com", Token: "token"},
		[]string{"registry"},
		ScanOptions{Platform: "linux/arm64"},
	)

	assert.Equal(t, "linux/arm64", config.Platform)
	assert.Equal(t, []string{"registry"}, config.Sources)
	require.Len(t, config.RegistryOptions.Credentials, 1)
	assert.Equal(t, "registry.example.com", config.RegistryOptions.Credentials[0].Authority)
	assert.Equal(t, "token", config.RegistryOptions.Credentials[0].Token)
}

func TestProviderConfigKeepsEmptyPlatformForCompatibility(t *testing.T) {
	config := getProviderConfig(RegistryCredentials{}, nil, ScanOptions{})

	assert.Empty(t, config.Platform)
	assert.Nil(t, config.Sources)
}
