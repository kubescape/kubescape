package imagescan

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrg/xdg"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type thresholdStubVulnerabilityProvider struct {
	metadataByID map[string]*vulnerability.Metadata
	errByID      map[string]error
}

func (s thresholdStubVulnerabilityProvider) PackageSearchNames(grypepkg.Package) []string {
	return nil
}

func (s thresholdStubVulnerabilityProvider) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}

func (s thresholdStubVulnerabilityProvider) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error) {
	if err, ok := s.errByID[ref.ID]; ok {
		return nil, err
	}

	if metadata, ok := s.metadataByID[ref.ID]; ok {
		return metadata, nil
	}

	return nil, errors.New("metadata not found")
}

func (s thresholdStubVulnerabilityProvider) Close() error {
	return nil
}

func makeThresholdTestMatch(id string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        id,
				Namespace: "nvd",
			},
		},
		Package: grypepkg.Package{
			ID:      grypepkg.ID("pkg-" + id),
			Name:    "pkg-" + id,
			Version: "1.0.0",
		},
	}
}

type stubVulnerabilityProvider struct {
	metadataByID map[string]*vulnerability.Metadata
	errByID      map[string]error
}

func (s stubVulnerabilityProvider) PackageSearchNames(grypepkg.Package) []string {
	return nil
}

func (s stubVulnerabilityProvider) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}

func (s stubVulnerabilityProvider) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error) {
	if err, ok := s.errByID[ref.ID]; ok {
		return nil, err
	}

	if metadata, ok := s.metadataByID[ref.ID]; ok {
		return metadata, nil
	}

	return nil, errors.New("metadata not found")
}

func (s stubVulnerabilityProvider) Close() error {
	return nil
}

func makeTestMatch(id string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        id,
				Namespace: "nvd",
			},
		},
		Package: grypepkg.Package{
			ID:      grypepkg.ID("pkg-" + id),
			Name:    "pkg-" + id,
			Version: "1.0.0",
		},
	}
}

func matchIDs(matches match.Matches) []string {
	ids := make([]string, 0, matches.Count())
	for m := range matches.Enumerate() {
		ids = append(ids, m.Vulnerability.ID)
	}
	return ids
}

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

func TestExceedsSeverityThreshold(t *testing.T) {
	provider := thresholdStubVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-high": {Severity: vulnerability.HighSeverity.String()},
			"CVE-low":  {Severity: vulnerability.LowSeverity.String()},
		},
		errByID: map[string]error{
			"CVE-error": errors.New("lookup failed"),
		},
	}

	tests := []struct {
		name      string
		threshold vulnerability.Severity
		matches   match.Matches
		want      bool
	}{
		{
			name:      "unknown threshold never fails the scan",
			threshold: vulnerability.UnknownSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-high"),
			),
			want: false,
		},
		{
			name:      "match equal to threshold fails the scan",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-high"),
				makeThresholdTestMatch("CVE-low"),
			),
			want: true,
		},
		{
			name:      "metadata errors are ignored when no remaining match exceeds threshold",
			threshold: vulnerability.MediumSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-error"),
				makeThresholdTestMatch("CVE-low"),
			),
			want: false,
		},
	}

	svc := &Service{vp: provider}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, svc.ExceedsSeverityThreshold(tt.threshold, tt.matches))
		})
	}
}

func TestValidateDBLoad(t *testing.T) {
	tests := []struct {
		name    string
		loadErr error
		status  *vulnerability.ProviderStatus
		wantErr string
	}{
		{
			name:    "load error is wrapped",
			loadErr: errors.New("boom"),
			wantErr: "failed to load vulnerability db: boom",
		},
		{
			name:    "nil status is rejected",
			wantErr: "unable to determine the status of the vulnerability db",
		},
		{
			name: "status error is wrapped",
			status: &vulnerability.ProviderStatus{
				Error: errors.New("status failure"),
			},
			wantErr: "db could not be loaded: status failure",
		},
		{
			name:   "valid status passes",
			status: &vulnerability.ProviderStatus{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDBLoad(tt.loadErr, tt.status)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
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

func TestNewDefaultDBConfig_SanitizationHarden(t *testing.T) {
	tests := []struct {
		name        string
		inputURL    string
		wantHost    string
		wantDefault bool
		wantErr     bool
	}{
		{
			name:        "valid URL with leading trailing spaces",
			inputURL:    "  https://custom-registry.io/db   ",
			wantHost:    "custom-registry.io",
			wantDefault: false,
			wantErr:     false,
		},
		{
			name:        "valid URL with trailing newline",
			inputURL:    "https://custom-registry.io/db\n",
			wantHost:    "custom-registry.io",
			wantDefault: false,
			wantErr:     false,
		},
		{
			name:        "whitespace only input falls back to default",
			inputURL:    "   ",
			wantDefault: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			distCfg, _, _, err := NewDefaultDBConfig(tt.inputURL)

			if (err != nil) != tt.wantErr {
				t.Fatalf("NewDefaultDBConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantDefault {
				if distCfg.LatestURL != defaultGrypeListingURL {
					t.Fatalf("expected default URL %q, got %q", defaultGrypeListingURL, distCfg.LatestURL)
				}
				return
			}

			if !strings.Contains(distCfg.LatestURL, tt.wantHost) {
				t.Fatalf("expected URL to contain host %q, got %q", tt.wantHost, distCfg.LatestURL)
			}
		})
	}
}

func TestFilterMatchesBasedOnSeverity(t *testing.T) {
	provider := stubVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-high": {
				Severity: "high",
			},
			"CVE-medium": {
				Severity: "medium",
			},
		},
		errByID: map[string]error{
			"CVE-error": errors.New("lookup failed"),
		},
	}

	remainingMatches := match.NewMatches(
		makeTestMatch("CVE-high"),
		makeTestMatch("CVE-medium"),
		makeTestMatch("CVE-error"),
	)

	t.Run("nil severity exceptions keep all matches", func(t *testing.T) {
		filtered := filterMatchesBasedOnSeverity(nil, remainingMatches, provider)
		assert.ElementsMatch(t, []string{"CVE-high", "CVE-medium", "CVE-error"}, matchIDs(filtered))
	})

	t.Run("empty severity exceptions keep all matches", func(t *testing.T) {
		filtered := filterMatchesBasedOnSeverity([]string{}, remainingMatches, provider)
		assert.ElementsMatch(t, []string{"CVE-high", "CVE-medium", "CVE-error"}, matchIDs(filtered))
	})

	t.Run("excluded severities are removed and metadata errors are skipped", func(t *testing.T) {
		filtered := filterMatchesBasedOnSeverity([]string{"HIGH"}, remainingMatches, provider)
		assert.ElementsMatch(t, []string{"CVE-medium"}, matchIDs(filtered))
	})
}

func TestGetMatchers(t *testing.T) {
	t.Run("default matchers", func(t *testing.T) {
		matchers := getMatchers(true)
		assert.NotNil(t, matchers)
		assert.NotEmpty(t, matchers)
	})

	t.Run("custom matchers", func(t *testing.T) {
		matchers := getMatchers(false)
		assert.NotNil(t, matchers)
		assert.NotEmpty(t, matchers)
	})
}

func TestNewScanServiceIntegration(t *testing.T) {
	distCfg, installCfg, _, _ := NewDefaultDBConfig("")

	svc, err := NewScanService(distCfg, installCfg)
	require.NoError(t, err)
	defer svc.Close()
	assert.True(t, svc.useDefaultMatchers)
}
