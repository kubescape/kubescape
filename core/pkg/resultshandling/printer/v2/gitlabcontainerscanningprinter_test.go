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
		// a local source is a path, kept whole, whether or not it has a "/" or a ":"
		{"docker-archive:app.tar", "docker-archive:app.tar:latest"},
		{"docker-archive:./app.tar", "docker-archive:./app.tar:latest"},
		{`docker-archive:C:\images\app.tar`, `docker-archive:C:\images\app.tar:latest`},
		{"OCI-Archive:app.tar", "OCI-Archive:app.tar:latest"},
		{"dir:.", "dir:.:latest"},
		// a daemon or registry scheme is followed by a reference
		{"docker:nginx", "docker:nginx:latest"},
		{"docker:nginx:1.25", "docker:nginx:1.25"},
		{"registry:localhost:5000/app", "registry:localhost:5000/app:latest"},
		{"podman:nginx@sha256:abc", "podman:nginx:latest@sha256:abc"},
		// what follows a daemon or registry scheme is a reference, even when the
		// image is named like a scheme
		{"docker:dir:latest", "docker:dir:latest"},
		{"docker:registry:2", "docker:registry:2"},
		{"image:dir:latest", "image:dir:latest"},
		{"docker:dir", "docker:dir:latest"},
		{"podman:docker-archive@sha256:abc", "podman:docker-archive:latest@sha256:abc"},
		{"registry:registry:2", "registry:registry:2"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeImageRef(tt.input))
		})
	}
}

// GitLab keys a container-scanning finding by its image without the tag, which it
// takes to be what follows the last ":" unless that reads as a version
// (Locations::ContainerScanning#docker_image_name_without_tag). Two archives, or two
// images named through a scheme, are still two images to it.
func TestGitLabContainerScanningPrinter_SourceSchemeInputsKeepDistinctImages(t *testing.T) {
	inputs := []string{"docker-archive:frontend.tar", "docker-archive:backend.tar", "docker:nginx", "docker:redis"}
	var imageScanData []cautils.ImageScanData
	for _, image := range inputs {
		imageScanData = append(imageScanData, cautils.ImageScanData{
			Image:   image,
			Matches: match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", "openssl", "a")),
		})
	}
	report := printContainerScanning(t, imageScanData)

	require.Len(t, report.Vulnerabilities, len(inputs))
	gitLabImages := make(map[string]bool)
	for _, vulnerability := range report.Vulnerabilities {
		image := vulnerability.Location.Image
		gitLabImages[image[:max(strings.LastIndex(image, ":"), 0)]] = true
	}
	assert.Len(t, gitLabImages, len(inputs), "images GitLab tells apart: %v", gitLabImages)
}

// An image named like a source scheme, pulled through a daemon or registry scheme,
// keeps the tag it was given: "docker:registry:2" is the image registry:2, not an
// untagged "registry:2" that needs ":latest".
func TestGitLabContainerScanningPrinter_ImageNamedLikeASchemeKeepsItsTag(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{{
		Image:   "docker:registry:2",
		Matches: match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", "openssl", "a")),
	}})

	require.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, "docker:registry:2", report.Vulnerabilities[0].Location.Image)
}

// GitLab tracks a container finding by its location fingerprint, the image name and the
// package (container_scanning.rb fingerprint_data), and leaves the operating system out.
// docker_image_name_without_tag drops the tag only when it is not a version, so the
// fixture uses a non-version tag and the helper below strips it the same way. The
// platform still reaches the report, but GitLab merges the variants of one image into
// one vulnerability, as docs/gitlab-ci.md says.
func TestGitLabContainerScanningPrinter_MultiPlatformSharesGitLabFingerprint(t *testing.T) {
	report := printContainerScanning(t, []cautils.ImageScanData{
		{
			Image:    "app:stable",
			Platform: "linux/amd64",
			Context:  grypepkg.Context{Distro: distro.New(distro.Alpine, "3.20.1", "")},
			Matches:  match.NewMatches(containerScanningMatch("CVE-2024-0001", "High", "openssl", "a")),
		},
		{
			Image:    "app:stable",
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
	assert.NotEqual(t, amd.ID, arm.ID, "the report keeps one finding per platform")

	gitLabFingerprint := func(v gitLabContainerVulnerability) string {
		image := v.Location.Image
		return image[:max(strings.LastIndex(image, ":"), 0)] + ":" + v.Location.Dependency.Package.Name
	}
	assert.Equal(t, gitLabFingerprint(amd), gitLabFingerprint(arm), "GitLab does not use the operating system, so the platforms share its fingerprint")
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

func TestGitLabContainerScanningPrinter_ExploitDetails(t *testing.T) {
	exploited := containerScanningMatch("CVE-2024-0009", "Critical", "openssl", "a", "3.3.2")
	exploited.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: "CVE-2024-0009"}}
	exploited.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0009", EPSS: 0.5, Percentile: 0.9}}

	report := printContainerScanning(t, []cautils.ImageScanData{{Image: "app:1.0", Matches: match.NewMatches(exploited)}})

	require.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, map[string]gitLabDetail{
		"kev":  {Name: "Known exploited (CISA KEV)", Type: "value", Value: true},
		"epss": {Name: "EPSS exploit probability", Type: "text", Value: "50.0% (90th)"},
	}, report.Vulnerabilities[0].Details)
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

func TestGitLabContainerScanningActionPrint_NilWriterReturnsError(t *testing.T) {
	ctx := context.Background()
	cp := NewGitLabContainerScanningPrinter()
	require.Nil(t, cp.writer)

	imageData := []cautils.ImageScanData{{Image: "alpine:latest"}}
	err := cp.ActionPrint(ctx, nil, imageData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output writer is nil")
}

func TestGitLabContainerScanning_NilReceiverSafety(t *testing.T) {
	var cp *GitLabContainerScanningPrinter

	assert.NotPanics(t, func() {
		err := cp.ActionPrint(context.Background(), nil, nil)
		assert.Error(t, err)
	})

	assert.NotPanics(t, func() {
		err := cp.CloseWriter()
		assert.NoError(t, err)
	})

	assert.NotPanics(t, func() {
		err := cp.SetWriter(context.Background(), "")
		assert.Error(t, err)
	})

	assert.NotPanics(t, func() {
		cp.Score(100)
		cp.PrintNextSteps()
	})
}
