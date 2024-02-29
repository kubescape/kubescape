package imagescan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/grypeerr"
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
	"github.com/anchore/syft/cmd/syft/cli/options"
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

type packagesOptions struct {
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
}

func defaultPackagesOptions() *packagesOptions {
	defaultCatalogOpts := options.DefaultCatalog()

	// TODO(matthyx): assess this value
	defaultCatalogOpts.Parallelism = 4

	return &packagesOptions{
		Output:      options.DefaultOutput(),
		UpdateCheck: options.DefaultUpdateCheck(),
		Catalog:     defaultCatalogOpts,
	}
}

func getProviderConfig(creds RegistryCredentials) pkg.ProviderConfig {
	syftCreds := []image.RegistryCredentials{{Username: creds.Username, Password: creds.Password}}
	regOpts := &image.RegistryOptions{
		Credentials: syftCreds,
	}
	syftOpts := defaultPackagesOptions()
	pc := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions: regOpts,
			SBOMOptions:     syftOpts.Catalog.ToSBOMConfig(clio.Identification{}),
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
	dbCfg db.Config
}

func (s *Service) Scan(ctx context.Context, userInput string, creds RegistryCredentials) (*models.PresenterConfig, error) {
	var err error

	store, status, dbCloser, err := NewVulnerabilityDB(s.dbCfg, true)
	if err = validateDBLoad(err, status); err != nil {
		return nil, err
	}

	packages, pkgContext, sbom, err := pkg.Provide(userInput, getProviderConfig(creds))
	if err != nil {
		return nil, err
	}

	if dbCloser != nil {
		defer dbCloser.Close()
	}

	matcher := grype.VulnerabilityMatcher{
		Store:    *store,
		Matchers: getMatchers(),
	}

	remainingMatches, ignoredMatches, err := matcher.FindMatches(packages, pkgContext)
	if err != nil {
		if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
			return nil, err
		}
	}

	pb := models.PresenterConfig{
		Matches:          *remainingMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: store,
		SBOM:             sbom,
		AppConfig:        nil,
		DBStatus:         status,
	}
	return &pb, nil
}

func NewVulnerabilityDB(cfg db.Config, update bool) (*store.Store, *db.Status, *db.Closer, error) {
	return grype.LoadVulnerabilityDB(cfg, update)
}

func NewScanService(dbCfg db.Config) Service {
	return Service{dbCfg: dbCfg}
}

// ParseSeverity returns a Grype severity given a severity string
//
// Used as a thin wrapper for ease of access from one image scan package
func ParseSeverity(severity string) vulnerability.Severity {
	return vulnerability.ParseSeverity(severity)
}
