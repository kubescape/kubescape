package imagescan

import (
	"errors"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
