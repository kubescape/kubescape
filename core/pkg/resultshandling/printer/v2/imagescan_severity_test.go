package printer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type severityRegressionVulnerabilityProvider struct {
	metadataByID map[string]*vulnerability.Metadata
}

func (s severityRegressionVulnerabilityProvider) PackageSearchNames(grypepkg.Package) []string {
	return nil
}

func (s severityRegressionVulnerabilityProvider) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}

func (s severityRegressionVulnerabilityProvider) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error) {
	if metadata, ok := s.metadataByID[ref.ID]; ok {
		return metadata, nil
	}
	return nil, errors.New("metadata not found")
}

func (s severityRegressionVulnerabilityProvider) Close() error {
	return nil
}

func makeSeverityRegressionMatch(id string) match.Match {
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

// buildSeverityExceptionImageScanData builds an ImageScanData whose Matches
// simulate a severity exception having filtered "CVE-EXCEPTED" out, leaving
// only "CVE-KEPT". This mirrors what (*Service).Scan produces when
// severityExceptions are configured.
func buildSeverityExceptionImageScanData() cautils.ImageScanData {
	keptMatch := makeSeverityRegressionMatch("CVE-KEPT")

	filteredMatches := match.NewMatches(keptMatch)

	provider := severityRegressionVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-KEPT":     {ID: "CVE-KEPT", Severity: "High"},
			"CVE-EXCEPTED": {ID: "CVE-EXCEPTED", Severity: "Low"},
		},
	}

	return cautils.ImageScanData{
		Image: "test-image:latest",
		IgnoredMatches: []match.IgnoredMatch{
			{
				Match:              makeSeverityRegressionMatch("CVE-EXCEPTED"),
				AppliedIgnoreRules: []match.IgnoreRule{{Vulnerability: "CVE-EXCEPTED"}},
			},
		},
		Packages: []grypepkg.Package{
			{ID: grypepkg.ID("pkg-CVE-KEPT"), Name: "pkg-CVE-KEPT", Version: "1.0.0"},
			{ID: grypepkg.ID("pkg-CVE-EXCEPTED"), Name: "pkg-CVE-EXCEPTED", Version: "1.0.0"},
		},
		Matches:               filteredMatches,
		VulnerabilityProvider: provider,
		SBOM:                  &sbom.SBOM{},
	}
}

// TestJsonPrinter_ImageScan_HonorsSeverityExceptions is the regression test for
// the severity-exceptions report bug: JSON output must reflect Matches (the
// severity-filtered set), not RemainingMatches, or excepted CVEs still show up
// in the report despite the scan correctly excluding them everywhere else.
func TestJsonPrinter_ImageScan_HonorsSeverityExceptions(t *testing.T) {
	imageScanData := buildSeverityExceptionImageScanData()

	tmp, err := os.CreateTemp("", "json-severity-exception-*.json")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	jp := NewJsonPrinter()
	jp.writer = tmp

	jp.ActionPrint(context.Background(), nil, []cautils.ImageScanData{imageScanData})

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	var ids []string
	for _, m := range doc.Matches {
		ids = append(ids, m.Vulnerability.ID)
	}

	assert.Contains(t, ids, "CVE-KEPT")
	assert.NotContains(t, ids, "CVE-EXCEPTED", "severity-excepted CVE must not appear in JSON report output")
}

// TestSARIFPrinter_ImageScan_HonorsSeverityExceptions is the SARIF counterpart
// of TestJsonPrinter_ImageScan_HonorsSeverityExceptions: see that test for the
// bug this guards against.
func TestSARIFPrinter_ImageScan_HonorsSeverityExceptions(t *testing.T) {
	imageScanData := buildSeverityExceptionImageScanData()

	tmp, err := os.CreateTemp("", "sarif-severity-exception-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	sp := NewSARIFPrinter()
	sp.writer = tmp

	require.NoError(t, sp.printImageScan(context.Background(), imageScanData))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	content := string(raw)
	assert.Contains(t, content, "CVE-KEPT")
	assert.NotContains(t, content, "CVE-EXCEPTED", "severity-excepted CVE must not appear in SARIF report output")
}
