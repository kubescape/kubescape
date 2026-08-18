package imagescan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/kubescape/kubescape/v3/core/cautils"
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

func makeThresholdTestMatchWithFixState(id string, state vulnerability.FixState) match.Match {
	m := makeThresholdTestMatch(id)
	m.Vulnerability.Fix.State = state
	return m
}

func makeThresholdTestMatchWithMetadata(id, severity string) match.Match {
	m := makeThresholdTestMatch(id)
	m.Vulnerability.Metadata = &vulnerability.Metadata{Severity: severity}
	return m
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

func TestApplyDBFreshness(t *testing.T) {
	builtAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)

	tests := []struct {
		name     string
		status   *vulnerability.ProviderStatus
		wantSet  bool
	}{
		{
			name:    "nil status leaves field unset",
			status:  nil,
			wantSet: false,
		},
		{
			name:    "zero Built leaves field unset",
			status:  &vulnerability.ProviderStatus{},
			wantSet: false,
		},
		{
			name: "Built is surfaced",
			status: &vulnerability.ProviderStatus{
				Built: builtAt,
			},
			wantSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := &cautils.ImageScanData{}
			applyDBFreshness(pb, tt.status)
			if tt.wantSet {
				require.NotNil(t, pb.VulnDBBuilt)
				assert.Equal(t, builtAt, *pb.VulnDBBuilt)
			} else {
				assert.Nil(t, pb.VulnDBBuilt)
			}
		})
	}
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
			name: "unknown",
			want: vulnerability.UnknownSeverity,
		},
		{
			name: "important",
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

func TestGetProviderConfig(t *testing.T) {
	tests := []struct {
		name      string
		creds     RegistryCredentials
		wantCreds []image.RegistryCredentials
	}{
		{
			name: "Both Non Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "password",
			},
			wantCreds: []image.RegistryCredentials{{Username: "username", Password: "password"}},
		},
		{
			name: "Password Empty",
			creds: RegistryCredentials{
				Username: "username",
				Password: "",
			},
			wantCreds: nil,
		},
		{
			name: "Username Empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "password",
			},
			wantCreds: nil,
		},
		{
			name: "Both empty",
			creds: RegistryCredentials{
				Username: "",
				Password: "",
			},
			wantCreds: nil,
		},
		{
			name: "Token with authority",
			creds: RegistryCredentials{
				Authority: "registry.example.com",
				Token:     "token",
			},
			wantCreds: []image.RegistryCredentials{{Authority: "registry.example.com", Token: "token"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerConfig := getProviderConfig(tt.creds, nil)
			assert.NotNil(t, providerConfig)
			assert.Equal(t, true, providerConfig.GenerateMissingCPEs)
			assert.Equal(t, tt.wantCreds, providerConfig.RegistryOptions.Credentials)
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
	if testing.Short() || os.Getenv("KUBESCAPE_INTEGRATION_TESTS") != "1" {
		t.Skip("skipping integration test; set KUBESCAPE_INTEGRATION_TESTS=1 to run")
	}
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
			"CVE-high":         {Severity: vulnerability.HighSeverity.String()},
			"CVE-low":          {Severity: vulnerability.LowSeverity.String()},
			"CVE-high-fixed":   {Severity: vulnerability.HighSeverity.String()},
			"CVE-high-unfixed": {Severity: vulnerability.HighSeverity.String()},
		},
		errByID: map[string]error{
			"CVE-error": errors.New("lookup failed"),
		},
	}

	tests := []struct {
		name        string
		threshold   vulnerability.Severity
		matches     match.Matches
		onlyFixable bool
		want        bool
	}{
		{
			name:      "unknown threshold never fails the scan",
			threshold: vulnerability.UnknownSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-high"),
			),
			onlyFixable: false,
			want:        false,
		},
		{
			name:      "match equal to threshold fails the scan",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-high"),
				makeThresholdTestMatch("CVE-low"),
			),
			onlyFixable: false,
			want:        true,
		},
		{
			name:      "metadata errors are ignored when no remaining match exceeds threshold",
			threshold: vulnerability.MediumSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatch("CVE-error"),
				makeThresholdTestMatch("CVE-low"),
			),
			onlyFixable: false,
			want:        false,
		},
		{
			name:      "embedded metadata gates when provider lookup fails",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithMetadata("CVE-error", vulnerability.CriticalSeverity.String()),
			),
			onlyFixable: false,
			want:        true,
		},
		{
			name:      "empty embedded severity falls back to provider metadata",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithMetadata("CVE-high", ""),
			),
			onlyFixable: false,
			want:        true,
		},
		{
			name:      "unrecognized embedded severity falls back to provider metadata",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithMetadata("CVE-high", "important"),
			),
			onlyFixable: false,
			want:        true,
		},
		{
			name:      "explicit unknown embedded severity falls back to provider metadata",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithMetadata("CVE-high", vulnerability.UnknownSeverity.String()),
			),
			onlyFixable: false,
			want:        true,
		},
		{
			name:      "onlyFixable ignores an unfixable CVE at or above threshold",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithFixState("CVE-high-unfixed", vulnerability.FixStateNotFixed),
			),
			onlyFixable: true,
			want:        false,
		},
		{
			name:      "onlyFixable still fails on a fixable CVE at or above threshold",
			threshold: vulnerability.HighSeverity,
			matches: match.NewMatches(
				makeThresholdTestMatchWithFixState("CVE-high-fixed", vulnerability.FixStateFixed),
			),
			onlyFixable: true,
			want:        true,
		},
	}

	svc := &Service{vp: provider}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, svc.ExceedsSeverityThreshold(tt.threshold, tt.matches, tt.onlyFixable))
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
	assert.Equal(t, "https://search.maven.org/solrsearch/select", cfg.Java.MavenBaseURL)
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

	t.Run("metadata lookup errors preserve matches", func(t *testing.T) {
		filtered := filterMatchesBasedOnSeverity([]string{"HIGH"}, remainingMatches, provider)
		assert.ElementsMatch(t, []string{"CVE-medium", "CVE-error"}, matchIDs(filtered))
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
	if testing.Short() || os.Getenv("KUBESCAPE_INTEGRATION_TESTS") != "1" {
		t.Skip("skipping integration test; set KUBESCAPE_INTEGRATION_TESTS=1 to run")
	}
	distCfg, installCfg, _, _ := NewDefaultDBConfig("")

	svc, err := NewScanService(distCfg, installCfg)
	require.NoError(t, err)
	defer svc.Close()
	assert.True(t, svc.useDefaultMatchers)
}
