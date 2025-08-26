package imagescan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/kubescape/kubescape/v3/core/cautils"
)

const (
	defaultGrypeListingURL = "https://grype.anchore.io/databases"
	defaultDBDirName       = "grypedb"
)

type RegistryCredentials struct {
	Username string
	Password string
}

func (c RegistryCredentials) IsEmpty() bool {
	return c.Username == "" || c.Password == ""
}

func NewDefaultDBConfig() (distribution.Config, installation.Config, bool) {
	dir := filepath.Join(xdg.CacheHome, defaultDBDirName)
	url := defaultGrypeListingURL
	shouldUpdate := true

	return distribution.Config{
			LatestURL: url,
		}, installation.Config{
			DBRootDir: dir,
		}, shouldUpdate
}

func getMatchers(useDefaultMatchers bool) []match.Matcher {
	if useDefaultMatchers {
		return matcher.NewDefaultMatchers(defaultMatcherConfig())
	}
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{MavenBaseURL: "https://search.maven.org/solrsearch/select"},
				UseCPEs:              true,
			},
			Ruby:       ruby.MatcherConfig{UseCPEs: true},
			Python:     python.MatcherConfig{UseCPEs: true},
			Dotnet:     dotnet.MatcherConfig{UseCPEs: true},
			Javascript: javascript.MatcherConfig{UseCPEs: true},
			Golang:     golang.MatcherConfig{UseCPEs: true},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}

func defaultMatcherConfig() matcher.Config {
	return matcher.Config{
		Java: java.MatcherConfig{
			ExternalSearchConfig: java.ExternalSearchConfig{MavenBaseURL: "https://search.maven.org/solrsearch/select"},
			UseCPEs:              false,
		},
		Ruby:       ruby.MatcherConfig{UseCPEs: false},
		Python:     python.MatcherConfig{UseCPEs: false},
		Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
		Javascript: javascript.MatcherConfig{UseCPEs: false},
		Golang: golang.MatcherConfig{
			UseCPEs:                                false,
			AlwaysUseCPEForStdlib:                  true,
			AllowMainModulePseudoVersionComparison: false,
		},
		Stock: stock.MatcherConfig{UseCPEs: true},
	}
}

func validateDBLoad(loadErr error, status *vulnerability.ProviderStatus) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the vulnerability db")
	}
	if status.Error != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Error)
	}
	return nil
}

func getProviderConfig(creds RegistryCredentials) pkg.ProviderConfig {
	syftCreds := []image.RegistryCredentials{{Username: creds.Username, Password: creds.Password}}
	regOpts := &image.RegistryOptions{
		Credentials: syftCreds,
	}
	pc := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions: regOpts,
			SBOMOptions:     syft.DefaultCreateSBOMConfig(),
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: true,
		},
	}
	return pc
}

// Service is a facade for image scanning functionality.
//
// It performs image scanning and everything needed in between.
type Service struct {
	useDefaultMatchers bool
	vp                 vulnerability.Provider
}

func getIgnoredMatches(vulnerabilityExceptions []string, vp vulnerability.Provider, packages []pkg.Package, pkgContext pkg.Context, useDefaultMatchers bool) (*match.Matches, []match.IgnoredMatch, error) {
	if vulnerabilityExceptions == nil {
		vulnerabilityExceptions = []string{}
	}

	var ignoreRules []match.IgnoreRule
	for _, exception := range vulnerabilityExceptions {
		rule := match.IgnoreRule{
			Vulnerability: exception,
		}
		ignoreRules = append(ignoreRules, rule)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vp,
		Matchers:              getMatchers(useDefaultMatchers),
		IgnoreRules:           ignoreRules,
	}

	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
			return nil, nil, err
		}
	}

	return remainingMatches, ignoredMatches, nil
}

// Filter the remaining matches based on severity exceptions.
func filterMatchesBasedOnSeverity(severityExceptions []string, remainingMatches match.Matches, vp vulnerability.Provider) match.Matches {
	if severityExceptions == nil {
		return remainingMatches
	}

	filteredMatches := match.NewMatches()

	for m := range remainingMatches.Enumerate() {
		metadata, err := vp.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			continue
		}

		// Skip this match if the severity of this match is present in severityExceptions.
		excludeSeverity := false
		for _, sever := range severityExceptions {
			if strings.ToUpper(metadata.Severity) == sever {
				excludeSeverity = true
				continue
			}
		}

		if !excludeSeverity {
			filteredMatches.Add(m)
		}
	}

	return filteredMatches
}

func (s *Service) Scan(_ context.Context, userInput string, creds RegistryCredentials, vulnerabilityExceptions, severityExceptions []string) (*cautils.ImageScanData, error) {
	packages, pkgContext, sbom, err := pkg.Provide(userInput, getProviderConfig(creds))
	if err != nil {
		return nil, err
	}

	remainingMatches, ignoredMatches, err := getIgnoredMatches(vulnerabilityExceptions, s.vp, packages, pkgContext, s.useDefaultMatchers)
	if err != nil {
		return nil, err
	}

	filteredMatches := filterMatchesBasedOnSeverity(severityExceptions, *remainingMatches, s.vp)

	pb := cautils.ImageScanData{
		Context:               pkgContext,
		IgnoredMatches:        ignoredMatches,
		Image:                 userInput,
		Matches:               filteredMatches,
		Packages:              packages,
		RemainingMatches:      remainingMatches,
		SBOM:                  sbom,
		VulnerabilityProvider: s.vp,
	}
	return &pb, nil
}

// ExceedsSeverityThreshold returns true if vulnerabilities in the scan results exceed the severity threshold, false otherwise.
//
// Values equal to the threshold are considered failing, too.
func (s *Service) ExceedsSeverityThreshold(severity vulnerability.Severity, matches match.Matches) bool {
	if severity == vulnerability.UnknownSeverity {
		return false
	}
	for m := range matches.Enumerate() {
		metadata, err := s.vp.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			continue
		}

		if vulnerability.ParseSeverity(metadata.Severity) >= severity {
			return true
		}
	}
	return false
}

func (s *Service) Close() {
	_ = s.vp.Close()
}

func NewVulnerabilityDB(distCfg distribution.Config, installCfg installation.Config, update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	return grype.LoadVulnerabilityDB(distCfg, installCfg, update)
}

func NewScanService(distCfg distribution.Config, installCfg installation.Config) (*Service, error) {
	return NewScanServiceWithMatchers(distCfg, installCfg, true)
}

func NewScanServiceWithMatchers(distCfg distribution.Config, installCfg installation.Config, useDefaultMatchers bool) (*Service, error) {
	vp, status, err := NewVulnerabilityDB(distCfg, installCfg, true)
	if err = validateDBLoad(err, status); err != nil {
		return nil, err
	}
	return &Service{
		vp:                 vp,
		useDefaultMatchers: useDefaultMatchers,
	}, nil
}

// ParseSeverity returns a Grype severity given a severity string
//
// Used as a thin wrapper for ease of access from one image scan package
func ParseSeverity(severity string) vulnerability.Severity {
	return vulnerability.ParseSeverity(severity)
}
