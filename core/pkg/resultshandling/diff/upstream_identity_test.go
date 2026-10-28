package diff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVulnerabilityDiffUpstreamVersionUpgrade(t *testing.T) {
	for _, tc := range []struct{ name, base, head string }{
		{"rpm", "pkg:rpm/redhat/openssl-libs@1.1.1k-15?arch=x86_64&epoch=0&upstream=openssl-1.1.1k-15.el8.src.rpm",
			"pkg:rpm/redhat/openssl-libs@1.1.1k-16?arch=x86_64&epoch=0&upstream=openssl-1.1.1k-16.el8.src.rpm"},
		{"hyphenated rpm source", "pkg:rpm/redhat/libfoo@1-2?upstream=lib-foo-source-1.0-2.el9.src.rpm",
			"pkg:rpm/redhat/libfoo@2-3?upstream=lib-foo-source-2.0-3.el9.src.rpm"},
		{"debian", "pkg:deb/ubuntu/coreutils@9.4-3ubuntu6?arch=amd64&upstream=coreutils%409.4-3ubuntu6",
			"pkg:deb/ubuntu/coreutils@9.4-3ubuntu7?arch=amd64&upstream=coreutils%409.4-3ubuntu7"},
		{"debian epoch", "pkg:deb/debian/libfoo@1?upstream=foo-source%401%3A1.2-3",
			"pkg:deb/debian/libfoo@2?upstream=foo-source%402%3A2.0-1"},
		{"unversioned debian source", "pkg:deb/debian/libfoo@1?upstream=foo-source%401.2-3",
			"pkg:deb/debian/libfoo@2?upstream=foo-source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changes, err := ComputeVulnerabilities(
				writeJSONReport(t, packageDiffDocument(tc.base, "old")),
				writeJSONReport(t, packageDiffDocument(tc.head, "new")),
			)
			require.NoError(t, err)
			require.Empty(t, changes.New)
			require.Empty(t, changes.Resolved)
			require.Len(t, changes.Unchanged, 1)
			require.Equal(t, tc.head, changes.Unchanged[0].PURL, "output retains the original full head PURL")
			require.Zero(t, NewVulnerabilitiesAtOrAbove(changes, "High"))
		})
	}
}

func TestVersionlessPackageURLRetainsOtherUpstreamIdentity(t *testing.T) {
	for _, tc := range []struct{ base, head string }{
		{"pkg:rpm/redhat/app@1?upstream=first-source-1-2.src.rpm", "pkg:rpm/redhat/app@2?upstream=second-source-2-3.src.rpm"},
		{"pkg:deb/debian/app@1?upstream=first-source%401.0", "pkg:deb/debian/app@2?upstream=second-source%402.0"},
		{"pkg:rpm/redhat/app@1?arch=x86_64&upstream=source-1-2.src.rpm", "pkg:rpm/redhat/app@2?arch=aarch64&upstream=source-2-3.src.rpm"},
		{"pkg:rpm/redhat/app@1?epoch=0&upstream=source-1-2.src.rpm", "pkg:rpm/redhat/app@2?epoch=1&upstream=source-2-3.src.rpm"},
		{"pkg:deb/debian/app@1?distro=debian-11&upstream=source%401", "pkg:deb/debian/app@2?distro=debian-12&upstream=source%402"},
		{"pkg:apk/alpine/app@1?upstream=source%401", "pkg:apk/alpine/app@2?upstream=source%402"},
		{"pkg:maven/org/app@1?upstream=source-1-2.src.rpm", "pkg:maven/org/app@2?upstream=source-2-3.src.rpm"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			changes, err := ComputeVulnerabilities(
				writeJSONReport(t, packageDiffDocument(tc.base, "old")),
				writeJSONReport(t, packageDiffDocument(tc.head, "new")),
			)
			require.NoError(t, err)
			require.Len(t, changes.New, 1)
			require.Len(t, changes.Resolved, 1)
			require.Empty(t, changes.Unchanged)
		})
	}
}

func TestVersionlessPackageURLLeavesUnrecognizedUpstreamValues(t *testing.T) {
	for _, tc := range []struct{ ecosystem, value string }{
		{"rpm", "source"}, {"rpm", "source-1.src.rpm"},
		{"rpm", "source--2.src.rpm"}, {"rpm", "source-1-.src.rpm"},
		{"rpm", "-1-2.src.rpm"}, {"rpm", "source-1-2.rpm"},
		{"deb", "source"}, {"deb", "%40version"},
		{"deb", "source%40"}, {"deb", "source%40one%40two"},
	} {
		t.Run(tc.ecosystem+"/"+tc.value, func(t *testing.T) {
			input := "pkg:" + tc.ecosystem + "/vendor/app?upstream=" + tc.value
			got, err := versionlessPackageURL(input)
			require.NoError(t, err)
			require.Equal(t, input, got)
		})
	}
}
