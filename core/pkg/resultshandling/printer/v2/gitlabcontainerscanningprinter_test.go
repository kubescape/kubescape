package printer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func containerScanningMatch(id, severity, packageName, location string, fixVersions ...string) match.Match {
	state := vulnerability.FixStateNotFixed
	if len(fixVersions) > 0 {
		state = vulnerability.FixStateFixed
	}
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: id, Namespace: "alpine:distro:alpine:3.20"},
			Metadata:  &vulnerability.Metadata{ID: id, Severity: severity},
			Fix:       vulnerability.Fix{Versions: fixVersions, State: state},
		},
		Package: grypepkg.Package{ID: grypepkg.ID(packageName + location + id), Name: packageName, Version: "1.0.0"},
	}
}

func printContainerScanning(t *testing.T, imageScanData []cautils.ImageScanData) gitLabContainerScanningReport {
	t.Helper()
	output := filepath.Join(t.TempDir(), "gl-container-scanning-report.json")
	cp := NewGitLabContainerScanningPrinter()
	require.NoError(t, cp.SetWriter(context.Background(), output))
	require.NoError(t, cp.ActionPrint(context.Background(), nil, imageScanData))
	require.NoError(t, cp.CloseWriter())

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	var report gitLabContainerScanningReport
	require.NoError(t, json.Unmarshal(content, &report))
	return report
}

func TestGitLabContainerScanningPrinter(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{
		{
			Image:   "registry.example.com/app:1.0",
			Context: grypepkg.Context{Distro: distro.New(distro.Alpine, "3.20.1", "")},
			Matches: match.NewMatches(
				containerScanningMatch("CVE-2024-0001", "Critical", "openssl", "a", "3.3.2"),
				containerScanningMatch("GHSA-aaaa-bbbb-cccc", "Negligible", "musl", "a"),
			),
		},
		{
			Image:    "registry.example.com/app:1.0",
			Platform: "linux/arm64",
			Matches:  match.NewMatches(containerScanningMatch("CVE-2024-0001", "Critical", "openssl", "a", "3.3.2")),
		},
	})

	assert.Equal(t, gitLabSASTReportVersion, report.Version)
	assert.Equal(t, "container_scanning", report.Scan.Type)
	assert.Equal(t, "success", report.Scan.Status)
	assert.Equal(t, gitLabScannerID, report.Scan.Scanner.ID)
	require.Len(t, report.Vulnerabilities, 3)

	critical := report.Vulnerabilities[0]
	assert.Equal(t, "CVE-2024-0001 in openssl 1.0.0", critical.Name)
	assert.Equal(t, "Critical", critical.Severity)
	assert.Equal(t, "Upgrade openssl to version 3.3.2.", critical.Solution)
	assert.Equal(t, "registry.example.com/app:1.0", critical.Location.Image)
	assert.Equal(t, "alpine 3.20.1", critical.Location.OperatingSystem)
	assert.Equal(t, gitLabDependency{Package: gitLabPackage{Name: "openssl"}, Version: "1.0.0"}, critical.Location.Dependency)
	require.Len(t, critical.Identifiers, 1)
	assert.Equal(t, "cve", critical.Identifiers[0].Type)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", critical.Identifiers[0].URL)

	negligible := report.Vulnerabilities[1]
	assert.Equal(t, "Info", negligible.Severity)
	assert.Contains(t, negligible.Description, "(severity: Info).")
	assert.Empty(t, negligible.Solution)
	assert.Equal(t, "ghsa", negligible.Identifiers[0].Type)

	arm := report.Vulnerabilities[2]
	assert.Equal(t, "Unknown (linux/arm64)", arm.Location.OperatingSystem)
	assert.Contains(t, arm.Description, "Scanned platform: linux/arm64.")
	assert.NotEqual(t, critical.ID, arm.ID, "platform variants are tracked separately")
}

func TestGitLabContainerScanningPrinter_CollapsesDuplicateFindings(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{{
		Image: "app:1.0",
		Matches: match.NewMatches(
			containerScanningMatch("ALAS-2024-0003", "", "curl", "/usr/bin"),
			containerScanningMatch("CVE-2024-0002", "High", "zlib", "/lib/a", "1.2.13"),
			containerScanningMatch("CVE-2024-0002", "High", "zlib", "/lib/b", "1.2.14"),
		),
	}})

	require.Len(t, report.Vulnerabilities, 2)
	assert.Equal(t, "ALAS-2024-0003 in curl 1.0.0", report.Vulnerabilities[0].Name)
	assert.Equal(t, "Unknown", report.Vulnerabilities[0].Severity)
	assert.Equal(t, "Package curl version 1.0.0 is affected by ALAS-2024-0003 (severity: Unknown).", report.Vulnerabilities[0].Description)
	assert.Equal(t, "alas", report.Vulnerabilities[0].Identifiers[0].Type)
	assert.Equal(t, "CVE-2024-0002 in zlib 1.0.0", report.Vulnerabilities[1].Name)
	assert.Equal(t, "Upgrade zlib to version 1.2.13, 1.2.14.", report.Vulnerabilities[1].Solution, "fix versions from duplicate findings are merged")
}

func TestGitLabContainerScanningPrinter_UntaggedImagesNormalized(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{
		{
			Image: "nginx",
			Matches: match.NewMatches(
				containerScanningMatch("CVE-2024-0001", "High", "openssl", "a", "3.3.2"),
			),
		},
		{
			Image: "redis",
			Matches: match.NewMatches(
				containerScanningMatch("CVE-2024-0001", "High", "openssl", "a", "3.3.2"),
			),
		},
	})

	require.Len(t, report.Vulnerabilities, 2)
	assert.Equal(t, "nginx:latest", report.Vulnerabilities[0].Location.Image)
	assert.Equal(t, gitLabImageVulnerabilityID("nginx:latest", "openssl", "1.0.0", "CVE-2024-0001", ""), report.Vulnerabilities[0].ID)

	assert.Equal(t, "redis:latest", report.Vulnerabilities[1].Location.Image)
	assert.Equal(t, gitLabImageVulnerabilityID("redis:latest", "openssl", "1.0.0", "CVE-2024-0001", ""), report.Vulnerabilities[1].ID)
}

func TestNormalizeImageRef(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx", "nginx:latest"},
		{"redis", "redis:latest"},
		{"library/nginx", "library/nginx:latest"},
		{"docker.io/library/nginx", "docker.io/library/nginx:latest"},
		{"localhost:5000/app", "localhost:5000/app:latest"},
		{"registry.example.com/team/app", "registry.example.com/team/app:latest"},
		{"nginx:1.25", "nginx:1.25"},
		{"nginx:latest", "nginx:latest"},
		{"localhost:5000/app:v1", "localhost:5000/app:v1"},
		{"nginx@sha256:abc", "nginx:latest@sha256:abc"},
		{"nginx:1.0@sha256:abc", "nginx:1.0@sha256:abc"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeImageRef(tt.input))
		})
	}
}

func TestGitLabContainerScanningPrinter_MultiPlatformDistinctFingerprints(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{
		{
			Image:    "app:1.0",
			Platform: "linux/amd64",
			Context:  grypepkg.Context{Distro: distro.New(distro.Alpine, "3.20.1", "")},
			Matches:  match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", "openssl", "a")),
		},
		{
			Image:    "app:1.0",
			Platform: "linux/arm64",
			Context:  grypepkg.Context{Distro: distro.New(distro.Alpine, "3.20.1", "")},
			Matches:  match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", "openssl", "a")),
		},
	})

	require.Len(t, report.Vulnerabilities, 2)
	amd := report.Vulnerabilities[0]
	arm := report.Vulnerabilities[1]

	assert.Equal(t, "alpine 3.20.1 (linux/amd64)", amd.Location.OperatingSystem)
	assert.Equal(t, "alpine 3.20.1 (linux/arm64)", arm.Location.OperatingSystem)
	assert.NotEqual(t, amd.Location.OperatingSystem, arm.Location.OperatingSystem, "platform distinguishes GitLab location fingerprint")
	assert.NotEqual(t, amd.ID, arm.ID)
}

func TestGitLabContainerScanningPrinter_BoundsLongNames(t *testing.T) {
	longPackage := strings.Repeat("é", 240)
	report := printContainerScanning(t, []cautils.ImageScanData{{
		Image:   "app:1.0",
		Matches: match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", longPackage, "a")),
	}})

	require.Len(t, report.Vulnerabilities, 1)
	vulnerability := report.Vulnerabilities[0]
	assert.Equal(t, gitLabMaxNameLength, utf8.RuneCountInString(vulnerability.Name))
	assert.True(t, utf8.ValidString(vulnerability.Name))
	assert.True(t, strings.HasSuffix(vulnerability.Name, "…"))
	assert.Equal(t, longPackage, vulnerability.Location.Dependency.Package.Name)
	assert.Contains(t, vulnerability.Description, longPackage+" version 1.0.0")
}

func TestTruncateRunes(t *testing.T) {
	assert.Equal(t, "short", truncateRunes("short", 5))
	assert.Equal(t, "abcd…", truncateRunes("abcdef", 5))
	assert.Equal(t, "éé…", truncateRunes("éééé", 3))
}

func TestGitLabContainerScanningPrinter_CleanImageWritesEmptyList(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	cp := NewGitLabContainerScanningPrinter()
	require.NoError(t, cp.SetWriter(context.Background(), output))
	require.NoError(t, cp.ActionPrint(context.Background(), nil, []cautils.ImageScanData{{Image: "alpine:3.20"}}))
	require.NoError(t, cp.CloseWriter())

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Contains(t, string(content), `"vulnerabilities": []`)
}

func TestGitLabContainerScanningPrinter_RequiresImages(t *testing.T) {
	cp := NewGitLabContainerScanningPrinter()
	require.NoError(t, cp.SetWriter(context.Background(), filepath.Join(t.TempDir(), "report.json")))
	t.Cleanup(func() { _ = cp.CloseWriter() })

	err := cp.ActionPrint(context.Background(), &cautils.OPASessionObj{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires scanned images")
}
