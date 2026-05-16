package imagescan

import (
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name string
		want vulnerability.Severity
	}{
		{
			name: "",
			want: vulnerability.UnknownSeverity,
		},
		{
			name: "negligible",
			want: vulnerability.NegligibleSeverity,
		},
		{
			name: "low",
			want: vulnerability.LowSeverity,
		},
		{
			name: "medium",
			want: vulnerability.MediumSeverity,
		},
		{
			name: "high",
			want: vulnerability.HighSeverity,
		},
		{
			name: "critical",
			want: vulnerability.CriticalSeverity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSeverity(tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		creds RegistryCredentials
		want  bool
	}{
		{
			name: "Both Non Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "password",
			},
			want: false,
		},
		{
			name: "Password Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "",
			},
			want: true,
		},
		{
			name: "Username Empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "password",
			},
			want: true,
		},
		{
			name: "Both empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "",
			},
			want: true,
		},
		{
			name:  "Empty struct",
			creds: RegistryCredentials{},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.creds.IsEmpty())
		})
	}
}

func TestGetProviderConfig(t *testing.T) {
	tests := []struct {
		name  string
		creds RegistryCredentials
	}{
		{
			name: "Both Non Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "password",
			},
		},
		{
			name: "Password Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "",
			},
		},
		{
			name: "Username Empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "password",
			},
		},
		{
			name: "Both empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerConfig := getProviderConfig(tt.creds)
			assert.NotNil(t, providerConfig)
			assert.Equal(t, true, providerConfig.GenerateMissingCPEs)
		})
	}
}

func TestNewScanServiceWithDefaultMatchers(t *testing.T) {
	// Test the Service struct creation with different useDefaultMatchers values
	// This test doesn't require a real database

	// Test with default matchers enabled
	svcWithDefault := &Service{
		useDefaultMatchers: true,
	}
	assert.True(t, svcWithDefault.useDefaultMatchers)

	// Test with default matchers disabled
	svcWithoutDefault := &Service{
		useDefaultMatchers: false,
	}
	assert.False(t, svcWithoutDefault.useDefaultMatchers)
}

func TestNewScanServiceWithMatchers(t *testing.T) {
	// Test the Service struct creation with different useDefaultMatchers values
	// This test doesn't require a real database

	// Test with default matchers enabled
	svcWithDefault := &Service{
		useDefaultMatchers: true,
	}
	assert.True(t, svcWithDefault.useDefaultMatchers)

	// Test with default matchers disabled
	svcWithoutDefault := &Service{
		useDefaultMatchers: false,
	}
	assert.False(t, svcWithoutDefault.useDefaultMatchers)
}

func TestNewScanServiceWithMatchersIntegration(t *testing.T) {
	// Test the actual NewScanServiceWithMatchers function
	distCfg, installCfg, _, _ := NewDefaultDBConfig("")

	// Test with default matchers enabled
	svcWithDefault, err := NewScanServiceWithMatchers(distCfg, installCfg, true)
	require.NoError(t, err)
	defer svcWithDefault.Close()
	assert.True(t, svcWithDefault.useDefaultMatchers)

	// Test with default matchers disabled
	svcWithoutDefault, err := NewScanServiceWithMatchers(distCfg, installCfg, false)
	require.NoError(t, err)
	defer svcWithoutDefault.Close()
	assert.False(t, svcWithoutDefault.useDefaultMatchers)
}

func TestNewDefaultDBConfig(t *testing.T) {
	tests := []struct {
		name       string
		grypeURL   string
		wantURL    string
		wantErr    string
		wantDir    string
		wantUpdate bool
	}{
		{
			name:       "default config uses bundled database URL",
			wantURL:    defaultGrypeListingURL,
			wantDir:    filepath.Join(xdg.CacheHome, defaultDBDirName),
			wantUpdate: true,
		},
		{
			name:       "custom https URL overrides default",
			grypeURL:   "https://example.com/grype/db/listing.json",
			wantURL:    "https://example.com/grype/db/listing.json",
			wantDir:    filepath.Join(xdg.CacheHome, defaultDBDirName),
			wantUpdate: true,
		},
		{
			name:       "custom http URL overrides default",
			grypeURL:   "http://example.com/custom-db/listing.json",
			wantURL:    "http://example.com/custom-db/listing.json",
			wantDir:    filepath.Join(xdg.CacheHome, defaultDBDirName),
			wantUpdate: true,
		},
		{
			name:     "custom URL without host is rejected",
			grypeURL: "http:///custom-db/listing.json",
			wantErr:  "invalid grype DB URL: missing host",
		},
		{
			name:     "unsupported URL scheme is rejected",
			grypeURL: "ftp://example.com/custom-db/listing.json",
			wantErr:  "invalid scheme: ftp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			distCfg, installCfg, shouldUpdate, err := NewDefaultDBConfig(tt.grypeURL)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantURL, distCfg.LatestURL)
			assert.Equal(t, tt.wantDir, installCfg.DBRootDir)
			assert.Equal(t, tt.wantUpdate, shouldUpdate)
		})
	}
}

func TestDefaultMatcherConfig(t *testing.T) {
	cfg := defaultMatcherConfig()
	assert.Equal(t, "https://search.maven.org/solrsearch/select", cfg.Java.ExternalSearchConfig.MavenBaseURL)
	assert.False(t, cfg.Java.UseCPEs)
	assert.False(t, cfg.Ruby.UseCPEs)
	assert.False(t, cfg.Python.UseCPEs)
	assert.False(t, cfg.Dotnet.UseCPEs)
	assert.False(t, cfg.Javascript.UseCPEs)
	assert.False(t, cfg.Golang.UseCPEs)
	assert.True(t, cfg.Golang.AlwaysUseCPEForStdlib)
	assert.False(t, cfg.Golang.AllowMainModulePseudoVersionComparison)
	assert.True(t, cfg.Stock.UseCPEs)
}
