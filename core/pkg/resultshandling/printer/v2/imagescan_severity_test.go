package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/owenrumney/go-sarif/v2/sarif"
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
	fixedMatch := makeSeverityRegressionMatch("CVE-FIXED")
	notAffectedMatch := makeSeverityRegressionMatch("CVE-NOT-AFFECTED")
	unchangedMatch := makeSeverityRegressionMatch("CVE-UNCHANGED")

	filteredMatches := match.NewMatches(keptMatch, fixedMatch, notAffectedMatch, unchangedMatch)

	provider := severityRegressionVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-KEPT":         {ID: "CVE-KEPT", Severity: "High"},
			"CVE-FIXED":        {ID: "CVE-FIXED", Severity: "High"},
			"CVE-NOT-AFFECTED": {ID: "CVE-NOT-AFFECTED", Severity: "High"},
			"CVE-UNCHANGED":    {ID: "CVE-UNCHANGED", Severity: "High"},
			"CVE-EXCEPTED":     {ID: "CVE-EXCEPTED", Severity: "Low"},
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
			{ID: grypepkg.ID("pkg-CVE-FIXED"), Name: "pkg-CVE-FIXED", Version: "1.0.0"},
			{ID: grypepkg.ID("pkg-CVE-NOT-AFFECTED"), Name: "pkg-CVE-NOT-AFFECTED", Version: "1.0.0"},
			{ID: grypepkg.ID("pkg-CVE-UNCHANGED"), Name: "pkg-CVE-UNCHANGED", Version: "1.0.0"},
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

	imageScanData.VexStatuses = map[string]cautils.VexStatus{
		"CVE-FIXED": {
			Status:        "fixed",
			Justification: "component_not_present",
		},
		"CVE-NOT-AFFECTED": {
			Status:        "not_affected",
			Justification: "vulnerable_code_not_in_execute_path",
		},
		"CVE-UNCHANGED": {
			Status:        "affected",
			Justification: "",
		},
	}

	tmp, err := os.CreateTemp("", "sarif-severity-exception-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	sp := NewSARIFPrinter()
	sp.writer = tmp

	require.NoError(t, sp.printImageScan(context.Background(), imageScanData))
	require.NoError(t, sp.printImageScan([]cautils.ImageScanData{imageScanData}))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	content := string(raw)
	assert.Contains(t, content, "CVE-KEPT")
	assert.NotContains(t, content, "CVE-EXCEPTED", "severity-excepted CVE must not appear in SARIF report output")

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.NotEmpty(t, report.Runs)
	assert.Equal(t, "Kubescape", report.Runs[0].Tool.Driver.Name)

	run := report.Runs[0]
	foundFixed, foundNotAffected, foundUnchanged := false, false, false

	for _, result := range run.Results {
		if result.RuleID != nil {
			if strings.HasPrefix(*result.RuleID, "CVE-FIXED") {
				foundFixed = true
				assert.Equal(t, "note", *result.Level)
				require.NotNil(t, result.Message.Text)
				assert.Contains(t, *result.Message.Text, "VEX Status: fixed. Justification: component_not_present")
			} else if strings.HasPrefix(*result.RuleID, "CVE-NOT-AFFECTED") {
				foundNotAffected = true
				assert.Equal(t, "note", *result.Level)
				require.NotNil(t, result.Message.Text)
				assert.Contains(t, *result.Message.Text, "VEX Status: not_affected. Justification: vulnerable_code_not_in_execute_path")
			} else if strings.HasPrefix(*result.RuleID, "CVE-UNCHANGED") {
				foundUnchanged = true
				if result.Level != nil {
					assert.NotEqual(t, "note", *result.Level)
				}
				if result.Message.Text != nil {
					assert.NotContains(t, *result.Message.Text, "VEX Status:")
				}
			} else if !strings.HasPrefix(*result.RuleID, "CVE-KEPT") {
				t.Logf("Found unexpected RuleID: %s", *result.RuleID)
			}
		} else {
			t.Log("Found result with nil RuleID")
		}
	}

	assert.True(t, foundFixed, "CVE-FIXED missing")
	assert.True(t, foundNotAffected, "CVE-NOT-AFFECTED missing")
	assert.True(t, foundUnchanged, "CVE-UNCHANGED missing")
}

const imageSARIFStdoutHelperEnv = "KUBESCAPE_TEST_IMAGE_SARIF_STDOUT_HELPER"

// TestSARIFPrinter_ImageScan_StdoutPipeCompletes runs the image SARIF printer
// in a subprocess whose stdout is an actual OS pipe. Reopening /dev/stdout to
// patch the report deadlocks because the process itself still owns the pipe's
// write end; the printer must instead render and patch in memory before its
// single write to stdout.
func TestSARIFPrinter_ImageScan_StdoutPipeCompletes(t *testing.T) {
	if os.Getenv(imageSARIFStdoutHelperEnv) == "1" {
		sp := NewSARIFPrinter()
		sp.SetWriter(context.Background(), "")
		if err := sp.printImageScan(context.Background(), buildSeverityExceptionImageScanData()); err != nil {
		if err := sp.printImageScan([]cautils.ImageScanData{buildSeverityExceptionImageScanData()}); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSARIFPrinter_ImageScan_StdoutPipeCompletes$") //nolint:gosec // G204: test subprocess re-executes test binary.
	cmd.Env = append(os.Environ(), imageSARIFStdoutHelperEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	raw, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("image SARIF output did not complete while stdout was a pipe")
	}
	require.NoError(t, err, stderr.String())

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.NotEmpty(t, report.Runs)
	assert.Equal(t, "Kubescape", report.Runs[0].Tool.Driver.Name)
}
