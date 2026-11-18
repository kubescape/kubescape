package diff

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// purlMatch is one grype match whose artifact carries a full syft PURL.
type purlMatch struct {
	id, severity, pkg, version, pkgType, purl string
}

func purlImageDocument(image string, matches ...purlMatch) map[string]any {
	encoded := make([]any, 0, len(matches))
	for _, m := range matches {
		encoded = append(encoded, map[string]any{
			"vulnerability": map[string]any{
				"id":       m.id,
				"severity": m.severity,
				"fix":      map[string]any{"versions": []string{}, "state": "not-fixed"},
			},
			"artifact": map[string]any{"name": m.pkg, "version": m.version, "type": m.pkgType, "purl": m.purl},
		})
	}
	return map[string]any{
		"matches": encoded,
		"source":  map[string]any{"type": "image", "target": map[string]any{"userInput": image}},
	}
}

func TestDistroRelease(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"alpine-3.19.1", "alpine-3.19"},
		{"alpine-3.19", "alpine-3.19"},
		{"alpine-3.20.0_alpha20240329", "alpine-3.20"},
		{"rhel-9.3", "rhel-9"},
		{"rhel-9", "rhel-9"},
		{"centos-7.9.2009", "centos-7"},
		{"rocky-9.4", "rocky-9"},
		{"almalinux-8.10", "almalinux-8"},
		{"ol-9.3", "ol-9"},
		// Already release-level, or not a distribution this knows.
		{"debian-12", "debian-12"},
		{"ubuntu-22.04", "ubuntu-22.04"},
		{"amzn-2023", "amzn-2023"},
		{"sles-15.5", "sles-15.5"},
		{"opensuse-leap-15.5", "opensuse-leap-15.5"},
		{"wolfi-20230201", "wolfi-20230201"},
		// Malformed values are kept as they are.
		{"alpine", "alpine"},
		{"alpine-", "alpine-"},
		{"-3.19.1", "-3.19.1"},
		{"alpine-edge", "alpine-edge"},
		{"rhel-.3", "rhel-.3"},
		{"rhel-x.3", "rhel-x.3"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, distroRelease(tc.in))
		})
	}
}

// TestVulnerabilityDiffIgnoresDistroPointReleases covers the common case of
// rebuilding an image on a newer patch of the same base: a finding that is
// still present must stay unchanged rather than being reported as resolved
// and new again.
func TestVulnerabilityDiffIgnoresDistroPointReleases(t *testing.T) {
	for _, tc := range []struct{ name, base, head string }{
		{"alpine patch release",
			"pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.19.1&upstream=busybox",
			"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.4&upstream=busybox"},
		{"ubi minor release",
			"pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=rhel-9.3&epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm",
			"pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm"},
		{"rocky minor release",
			"pkg:rpm/rocky/glibc@2.34-83.el9_3.7?arch=x86_64&distro=rocky-9.3&upstream=glibc-2.34-83.el9_3.7.src.rpm",
			"pkg:rpm/rocky/glibc@2.34-100.el9?arch=x86_64&distro=rocky-9.4&upstream=glibc-2.34-100.el9.src.rpm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changes, err := ComputeVulnerabilities(
				writeJSONReport(t, packageDiffDocument(tc.base, "old")),
				writeJSONReport(t, packageDiffDocument(tc.head, "new")),
			)
			require.NoError(t, err)
			assert.Empty(t, changes.New)
			assert.Empty(t, changes.Resolved)
			require.Len(t, changes.Unchanged, 1)
			assert.Equal(t, tc.head, changes.Unchanged[0].PURL, "output keeps the original head PURL")
			assert.Zero(t, NewVulnerabilitiesAtOrAbove(changes, "Low"))
		})
	}
}

// TestVulnerabilityDiffKeepsDistroReleaseBoundaries pins the other side: a
// move to another release of the distribution, or to another distribution,
// is still a different package.
func TestVulnerabilityDiffKeepsDistroReleaseBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, base, head string }{
		{"alpine branch", "pkg:apk/alpine/busybox@1?distro=alpine-3.19.4", "pkg:apk/alpine/busybox@2?distro=alpine-3.20.0"},
		{"rhel major", "pkg:rpm/redhat/openssl@1?distro=rhel-8.9", "pkg:rpm/redhat/openssl@2?distro=rhel-9.3"},
		{"ubuntu release", "pkg:deb/ubuntu/openssl@1?distro=ubuntu-22.04", "pkg:deb/ubuntu/openssl@2?distro=ubuntu-24.04"},
		{"other distribution", "pkg:rpm/redhat/openssl@1?distro=rhel-9.3", "pkg:rpm/redhat/openssl@2?distro=rocky-9.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changes, err := ComputeVulnerabilities(
				writeJSONReport(t, packageDiffDocument(tc.base, "old")),
				writeJSONReport(t, packageDiffDocument(tc.head, "new")),
			)
			require.NoError(t, err)
			assert.Len(t, changes.New, 1)
			assert.Len(t, changes.Resolved, 1)
			assert.Empty(t, changes.Unchanged)
		})
	}
}

// TestCompareReportsAlpinePatchBumpReportsOnlyRealChanges runs the whole
// report comparison the diff command uses on a base-image patch bump: one
// finding is fixed by the bump, one is introduced, and the rest carry over.
func TestCompareReportsAlpinePatchBumpReportsOnlyRealChanges(t *testing.T) {
	base := writeJSONReport(t, purlImageDocument("registry.example/app:1.0",
		purlMatch{"CVE-2024-0001", "High", "openssl", "3.1.4-r5", "apk", "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl"},
		purlMatch{"CVE-2024-0002", "Medium", "busybox", "1.36.1-r15", "apk", "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.19.1&upstream=busybox"},
		purlMatch{"CVE-2024-0003", "Critical", "zlib", "1.3.1-r0", "apk", "pkg:apk/alpine/zlib@1.3.1-r0?arch=x86_64&distro=alpine-3.19.1&upstream=zlib"},
	))
	head := writeJSONReport(t, purlImageDocument("registry.example/app:1.1",
		purlMatch{"CVE-2024-0001", "High", "openssl", "3.1.6-r0", "apk", "pkg:apk/alpine/openssl@3.1.6-r0?arch=x86_64&distro=alpine-3.19.4&upstream=openssl"},
		purlMatch{"CVE-2024-0002", "Medium", "busybox", "1.36.1-r20", "apk", "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.4&upstream=busybox"},
		purlMatch{"CVE-2024-0004", "High", "curl", "8.9.1-r0", "apk", "pkg:apk/alpine/curl@8.9.1-r0?arch=x86_64&distro=alpine-3.19.4&upstream=curl"},
	))

	kind, _, changes, err := CompareReports(base, head, Options{})
	require.NoError(t, err)
	require.Equal(t, VulnerabilityReport, kind)
	require.NotNil(t, changes)

	assert.Equal(t, []string{"CVE-2024-0004/curl"}, vulnerabilityIDs(changes.New))
	assert.Equal(t, []string{"CVE-2024-0003/zlib"}, vulnerabilityIDs(changes.Resolved))
	assert.ElementsMatch(t, []string{"CVE-2024-0001/openssl", "CVE-2024-0002/busybox"}, vulnerabilityIDs(changes.Unchanged))
	assert.Equal(t, 1, NewVulnerabilitiesAtOrAbove(changes, "High"), "only the curl finding is new")
}

// alpinePatchBumpReports is a base and head image report for a rebuild on the
// next patch of the same Alpine branch: busybox still carries its CVE and only
// the distro qualifier and package release changed.
func alpinePatchBumpReports(t *testing.T) (string, string) {
	t.Helper()
	base := writeJSONReport(t, purlImageDocument("registry.example/app:1.0",
		purlMatch{"CVE-2024-0002", "High", "busybox", "1.36.1-r15", "apk", "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.19.1&upstream=busybox"},
	))
	head := writeJSONReport(t, purlImageDocument("registry.example/app:1.1",
		purlMatch{"CVE-2024-0002", "High", "busybox", "1.36.1-r20", "apk", "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.4&upstream=busybox"},
	))
	return base, head
}

// TestVulnerabilityCIOutputsQuietOnDistroPointRelease checks every CI output
// of the image diff on a point-release bump: the finding is unchanged, so no
// output reports a new vulnerability and no pipeline gate fires.
func TestVulnerabilityCIOutputsQuietOnDistroPointRelease(t *testing.T) {
	base, head := alpinePatchBumpReports(t)
	_, _, cs, err := CompareReports(base, head, Options{})
	require.NoError(t, err)
	require.NotNil(t, cs)
	require.Len(t, cs.Unchanged, 1)

	t.Run("sarif", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, PrintVulnerabilitySARIF(&out, cs, ""))
		var report diffSARIFReport
		require.NoError(t, json.Unmarshal(out.Bytes(), &report))
		require.Len(t, report.Runs, 1)
		assert.Empty(t, report.Runs[0].Results)
	})
	t.Run("junit", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, PrintVulnerabilityJUnit(&out, cs, ""))
		assert.Contains(t, out.String(), `tests="0"`)
		assert.NotContains(t, out.String(), "CVE-2024-0002")
	})
	t.Run("markdown", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, PrintVulnerabilityMarkdown(&out, cs, ""))
		assert.Contains(t, out.String(), "| New | 0 |")
		assert.Contains(t, out.String(), "| Unchanged | 1 |")
	})
}

// TestVulnerabilitySARIFIdentityStableAcrossDistroPointReleases pins the
// identity GitHub code scanning tracks an alert by. The artifact location and
// partial fingerprint of a finding must not move when only the distro point
// release changes, or the alert is closed and a new one opened on every base
// image refresh. A different release is still a different identity.
func TestVulnerabilitySARIFIdentityStableAcrossDistroPointReleases(t *testing.T) {
	finding := func(purl string) VulnerabilityChange {
		return VulnerabilityChange{ID: "CVE-2024-0002", Severity: "High", Package: "busybox", Type: "apk", PURL: purl}
	}
	for _, tc := range []struct {
		name       string
		base, head string
		same       bool
	}{
		{"alpine patch release", "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-3.19.1", "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19.4", true},
		{"ubi minor release", "pkg:rpm/redhat/busybox@1-1.el9?distro=rhel-9.3", "pkg:rpm/redhat/busybox@1-2.el9?distro=rhel-9.4", true},
		{"alpine branch", "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19.4", "pkg:apk/alpine/busybox@1.37.0-r0?distro=alpine-3.20.0", false},
		{"debian release", "pkg:deb/debian/busybox@1?distro=debian-11", "pkg:deb/debian/busybox@2?distro=debian-12", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, head := finding(tc.base), finding(tc.head)
			assert.Equal(t, tc.same, vulnerabilityFingerprint(base) == vulnerabilityFingerprint(head), "fingerprint")
			assert.Equal(t, tc.same, vulnerabilityLocation(base) == vulnerabilityLocation(head), "artifact location")
		})
	}
}

func TestVulnerabilitySARIFLocationNamesTheRelease(t *testing.T) {
	location := vulnerabilityLocation(VulnerabilityChange{Package: "busybox", Type: "apk", PURL: "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.4"})
	unescaped, err := url.PathUnescape(strings.TrimPrefix(location, "packages/"))
	require.NoError(t, err)
	assert.Contains(t, unescaped, "distro=alpine-3.19")
	assert.NotContains(t, unescaped, "3.19.4", "the point release is not part of the location")
	assert.NotContains(t, unescaped, "1.36.1-r20", "the package version is not part of the location")
}
