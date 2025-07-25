package imagescan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
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
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
)

const (
	defaultGrypeListingURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"
	defaultDBDirName       = "grypedb"
)

type RegistryCredentials struct {
	Username string
	Password string
}

func (c RegistryCredentials) IsEmpty() bool {
	return c.Username == "" || c.Password == ""
}

// ExceedsSeverityThreshold returns true if vulnerabilities in the scan results exceed the severity threshold, false otherwise.
//
// Values equal to the threshold are considered failing, too.
func ExceedsSeverityThreshold(scanResults *models.PresenterConfig, severity vulnerability.Severity) bool {
	if scanResults.MetadataProvider == nil {
		return false
	}

	return grype.HasSeverityAtOrAbove(scanResults.MetadataProvider, severity, scanResults.Matches)
}

func NewDefaultDBConfig() (db.Config, bool) {
	dir := filepath.Join(xdg.CacheHome, defaultDBDirName)
	url := defaultGrypeListingURL
	shouldUpdate := true

	return db.Config{
		DBRootDir:  dir,
		ListingURL: url,
	}, shouldUpdate
}

func getMatchers() []matcher.Matcher {
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

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the vulnerability db")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
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
	dbCfg    db.Config
	dbCloser *db.Closer
	dbStatus *db.Status
	dbStore  *store.Store
}

func getIgnoredMatches(vulnerabilityExceptions []string, store *store.Store, packages []pkg.Package, pkgContext pkg.Context) (*match.Matches, []match.IgnoredMatch, error) {
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

	matcher := grype.VulnerabilityMatcher{
		Store:       *store,
		Matchers:    getMatchers(),
		IgnoreRules: ignoreRules,
	}

	remainingMatches, ignoredMatches, err := matcher.FindMatches(packages, pkgContext)
	if err != nil {
		if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
			return nil, nil, err
		}
	}

	return remainingMatches, ignoredMatches, nil
}

// Filter the remaing matches based on severity exceptions.
func filterMatchesBasedOnSeverity(severityExceptions []string, remainingMatches match.Matches, store *store.Store) match.Matches {
	if severityExceptions == nil {
		return remainingMatches
	}

	filteredMatches := match.NewMatches()

	for m := range remainingMatches.Enumerate() {
		metadata, err := store.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
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

func (s *Service) Scan(_ context.Context, userInput string, creds RegistryCredentials, vulnerabilityExceptions, severityExceptions []string) (*models.PresenterConfig, error) {
	packages, pkgContext, sbom, err := pkg.Provide(userInput, getProviderConfig(creds))
	if err != nil {
		return nil, err
	}

	remainingMatches, ignoredMatches, err := getIgnoredMatches(vulnerabilityExceptions, s.dbStore, packages, pkgContext)
	if err != nil {
		return nil, err
	}

	filteredMatches := filterMatchesBasedOnSeverity(severityExceptions, *remainingMatches, s.dbStore)

	pb := models.PresenterConfig{
		Matches:          filteredMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: s.dbStore,
		SBOM:             sbom,
		AppConfig:        nil,
		DBStatus:         s.dbStatus,
	}
	return &pb, nil
}

func (s *Service) Close() {
	s.dbCloser.Close()
}

func NewVulnerabilityDB(cfg db.Config, update bool) (*store.Store, *db.Status, *db.Closer, error) {
	return grype.LoadVulnerabilityDB(cfg, update)
}

func NewScanService(dbCfg db.Config) (*Service, error) {
	dbStore, dbStatus, dbCloser, err := NewVulnerabilityDB(dbCfg, true)
	if err = validateDBLoad(err, dbStatus); err != nil {
		return nil, err
	}
	return &Service{
		dbCfg:    dbCfg,
		dbCloser: dbCloser,
		dbStatus: dbStatus,
		dbStore:  dbStore,
	}, nil
}

// ParseSeverity returns a Grype severity given a severity string
//
// Used as a thin wrapper for ease of access from one image scan package
func ParseSeverity(severity string) vulnerability.Severity {
	return vulnerability.ParseSeverity(severity)
}
