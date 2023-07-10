package imagescan

import (
	"context"
	"errors"
	"fmt"

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
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/pkg/cataloger"
)

const (
	defaultGrypeListingURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"
)

func NewDefaultDBConfig() (db.Config, bool) {
	dir := "~/.test-deleteme/"
	url := defaultGrypeListingURL
	shouldUpdate := true

	return db.Config{
		DBRootDir:  dir,
		ListingURL: url,
	}, shouldUpdate
}

type Service struct {
	dbCfg db.Config
}

func (s *Service) Scan(ctx context.Context, userInput string) (*models.PresenterConfig, error) {
	var err error

	errs := make(chan error)

	store, status, dbCloser, err := grype.LoadVulnerabilityDB(s.dbCfg, true)
	if err = validateDBLoad(err, status); err != nil {
		errs <- err
		return nil, err
	}

	packages, pkgContext, sbom, err := pkg.Provide(userInput, getProviderConfig())
	if err != nil {
		return nil, err
	}

	if dbCloser != nil {
		defer dbCloser.Close()
	}

	// applyDistroHint(packages, &pkgContext, appConfig)

	vulnMatcher := grype.VulnerabilityMatcher{
		Store:    *store,
		Matchers: getMatchers(),
	}

	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		errs <- err
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

func getProviderConfig() pkg.ProviderConfig {
	regOpts := &image.RegistryOptions{
		InsecureSkipTLSVerify: true,
		// InsecureUseHTTP: true,
	}
	catOpts := cataloger.DefaultConfig()
	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:   regOpts,
			CatalogingOptions: catOpts,
			// Platform:               appConfig.Platform,
			// Name:                   appConfig.Name,
			// DefaultImagePullSource: appConfig.DefaultImagePullSource,
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: true,
		},
	}
}
