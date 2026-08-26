package imagescan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

const (
	defaultGrypeListingURL = "https://grype.anchore.io/databases"
	defaultDBDirName       = "grypedb"
)

type RegistryCredentials struct {
	Authority string
	Username  string
	Password  string
	Token     string
}

func (c RegistryCredentials) hasAuthenticator() bool {
	return c.Token != "" || (c.Username != "" && c.Password != "")
}

func NewDefaultDBConfig(grypeURL string, skipDBUpdate bool) (distribution.Config, installation.Config, bool, error) {
	dir := filepath.Join(xdg.CacheHome, defaultDBDirName)
	finalURL := defaultGrypeListingURL

	cleanedGrypeURL := strings.TrimSpace(grypeURL)

	if cleanedGrypeURL != "" {
		logger.L().Info(fmt.Sprintf("Using custom Grype database URL: %s", cleanedGrypeURL))

		parsed, err := url.ParseRequestURI(cleanedGrypeURL)
		if err != nil {
			return distribution.Config{}, installation.Config{}, false, err
		}

		if parsed.Host == "" {
			return distribution.Config{}, installation.Config{}, false, fmt.Errorf("invalid grype DB URL: missing host")
		}

		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return distribution.Config{}, installation.Config{}, false, fmt.Errorf("invalid scheme: %s", parsed.Scheme)
		}

		finalURL = cleanedGrypeURL
	}

	shouldUpdate := !skipDBUpdate

	return distribution.Config{
		LatestURL: finalURL,
	}, installation.Config{
		DBRootDir: dir,
	}, shouldUpdate, nil
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

func getProviderConfig(creds RegistryCredentials, sources []string, options ScanOptions) pkg.ProviderConfig {
	var syftCreds []image.RegistryCredentials
	if creds.hasAuthenticator() {
		syftCreds = append(syftCreds, image.RegistryCredentials{
			Authority: creds.Authority,
			Username:  creds.Username,
			Password:  creds.Password,
			Token:     creds.Token,
		})
	}
	regOpts := &image.RegistryOptions{
		Credentials: syftCreds,
	}
	pc := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions: regOpts,
			SBOMOptions:     syft.DefaultCreateSBOMConfig(),
			Sources:         sources,
			Platform:        options.Platform,
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
	vexClient          VexClient
	// sources specifies allowed provider sources (nil = all providers).
	// Used by MCP server to restrict scans to remote registry providers.
	sources []string
	// dbStatus carries the loaded vulnerability DB status so scan results can
	// surface DB freshness (ProviderStatus.Built). Nil when the DB failed to load.
	dbStatus *vulnerability.ProviderStatus
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
	if len(severityExceptions) == 0 {
		return remainingMatches
	}

	filteredMatches := match.NewMatches()

	for m := range remainingMatches.Enumerate() {
		//nolint:staticcheck // deprecated but replacing it requires refactoring
		metadata, err := vp.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			filteredMatches.Add(m)
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

func (s *Service) Scan(ctx context.Context, userInput string, creds RegistryCredentials, vulnerabilityExceptions, severityExceptions []string) (*cautils.ImageScanData, error) {
	return s.ScanWithOptions(ctx, userInput, creds, vulnerabilityExceptions, severityExceptions, ScanOptions{})
}

// ScanWithOptions scans an image using explicit source-selection options. In
// particular, Platform prevents a multi-architecture image index from silently
// resolving to the architecture of the machine running Kubescape.
func (s *Service) ScanWithOptions(ctx context.Context, userInput string, creds RegistryCredentials, vulnerabilityExceptions, severityExceptions []string, options ScanOptions) (*cautils.ImageScanData, error) {
	platform, err := NormalizePlatform(options.Platform)
	if err != nil {
		return nil, err
	}
	options.Platform = platform

	packages, pkgContext, sbom, err := pkg.Provide(userInput, getProviderConfig(creds, s.sources, options))
	if err != nil {
		return nil, err
	}

	remainingMatches, ignoredMatches, err := getIgnoredMatches(vulnerabilityExceptions, s.vp, packages, pkgContext, s.useDefaultMatchers)
	if err != nil {
		return nil, err
	}

	filteredMatches := filterMatchesBasedOnSeverity(severityExceptions, *remainingMatches, s.vp)

	vexStatuses, err := s.vexClient.GetVexStatuses(ctx, userInput)
	if err != nil {
		// Log error but continue scanning
		logger.L().Warning("Failed to fetch VEX statuses", helpers.Error(err))
	}

	pb := cautils.ImageScanData{
		Context:               pkgContext,
		IgnoredMatches:        ignoredMatches,
		Image:                 userInput,
		Platform:              platform,
		Matches:               filteredMatches,
		Packages:              packages,
		SBOM:                  sbom,
		VulnerabilityProvider: s.vp,
		VexStatuses:           vexStatuses,
	}

	applyDBFreshness(&pb, s.dbStatus)

	return &pb, nil
}

// applyDBFreshness sets VulnDBBuilt on the scan result from the loaded DB
// status. It is a no-op when the status is nil or the build time is unknown.
func applyDBFreshness(pb *cautils.ImageScanData, status *vulnerability.ProviderStatus) {
	if status != nil && !status.Built.IsZero() {
		pb.VulnDBBuilt = &status.Built
	}
}

// ExceedsSeverityThreshold returns true if vulnerabilities in the scan results exceed the severity threshold, false otherwise.
//
// Values equal to the threshold are considered failing, too. When onlyFixable is true, a CVE only
// counts toward the threshold if grype reports a fix state of "fixed" for it.
func (s *Service) ExceedsSeverityThreshold(severity vulnerability.Severity, matches match.Matches, onlyFixable bool) bool {
	if severity == vulnerability.UnknownSeverity {
		return false
	}
	for m := range matches.Enumerate() {
		metadata := m.Vulnerability.Metadata
		if metadata == nil || vulnerability.ParseSeverity(metadata.Severity) == vulnerability.UnknownSeverity {
			if s.vp == nil {
				continue
			}
			var err error
			//nolint:staticcheck // fallback for matches without a known embedded severity
			metadata, err = s.vp.VulnerabilityMetadata(m.Vulnerability.Reference)
			if err != nil {
				continue
			}
		}

		if vulnerability.ParseSeverity(metadata.Severity) < severity {
			continue
		}

		if onlyFixable && m.Vulnerability.Fix.State != vulnerability.FixStateFixed {
			continue
		}

		return true
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
	return NewScanServiceWithMatchersAndSources(distCfg, installCfg, useDefaultMatchers, nil, true)
}

// NewRemoteOnlyScanService creates a Service restricted to remote registry sources only,
// preventing resolution of local files or local daemon images (used by MCP server).
func NewRemoteOnlyScanService(distCfg distribution.Config, installCfg installation.Config) (*Service, error) {
	return NewScanServiceWithMatchersAndSources(distCfg, installCfg, true, []string{"registry"}, true)
}

func NewScanServiceWithMatchersAndSources(distCfg distribution.Config, installCfg installation.Config, useDefaultMatchers bool, sources []string, shouldUpdate bool) (*Service, error) {
	vp, status, err := NewVulnerabilityDB(distCfg, installCfg, shouldUpdate)
	if err = validateDBLoad(err, status); err != nil {
		return nil, wrapDBLoadError(err, shouldUpdate)
	}
	return &Service{
		vp:                 vp,
		dbStatus:           status,
		useDefaultMatchers: useDefaultMatchers,
		vexClient:          NewVexClient(),
		sources:            sources,
	}, nil
}

// wrapDBLoadError adds a hint when the database update was skipped and the
// load failed, so users know the local database must be usable first. The
// wording is neutral because the failure may be a missing, corrupt, or
// incompatible local database, not only an absent one.
func wrapDBLoadError(err error, shouldUpdate bool) error {
	if shouldUpdate {
		return err
	}
	return fmt.Errorf("%w; the local vulnerability database could not be used (update was skipped) — run once without --skip-db-update to download it", err)
}

// ParseSeverity returns a Grype severity given a severity string
//
// Used as a thin wrapper for ease of access from one image scan package
func ParseSeverity(severity string) vulnerability.Severity {
	return vulnerability.ParseSeverity(severity)
}
