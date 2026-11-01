package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func packageDiffDocument(purl, version string) map[string]any {
	doc := imageDocument("example.invalid/app:1", testMatch{
		id: "CVE-2026-1000", severity: "High", pkg: "parser", version: version, pkgType: "java-archive",
	})
	doc["matches"].([]any)[0].(map[string]any)["artifact"].(map[string]any)["purl"] = purl
	return doc
}

func TestVulnerabilityDiffSeparatesPackageNamespaces(t *testing.T) {
	base := writeJSONReport(t, packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0"))
	head := writeJSONReport(t, packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0"))
	changes, err := ComputeVulnerabilities(base, head)
	require.NoError(t, err)
	require.Len(t, changes.New, 1, "an unrelated package's CVE must not be marked unchanged")
	require.Len(t, changes.Resolved, 1)
	require.Empty(t, changes.Unchanged)
	require.Equal(t, 1, NewVulnerabilitiesAtOrAbove(changes, "High"))
}

func TestVulnerabilityDiffPreservesUpgradeSemanticsWithPURLs(t *testing.T) {
	for _, purls := range [][2]string{
		{"pkg:maven/org.first/parser@1.0", "pkg:maven/org.first/parser@2.0"},
		{"pkg:deb/debian/parser@1.0?arch=amd64", "pkg:deb/debian/parser@2.0?arch=amd64"},
		{"pkg:npm/%40scope/parser@1.0", "pkg:npm/%40scope/parser@2.0"},
		{"pkg:golang/example.invalid/parser@v1.0", "pkg:golang/example.invalid/parser@v2.0"},
	} {
		t.Run(purls[0], func(t *testing.T) {
			base := writeJSONReport(t, packageDiffDocument(purls[0], "1.0"))
			head := writeJSONReport(t, packageDiffDocument(purls[1], "2.0"))
			changes, err := ComputeVulnerabilities(base, head)
			require.NoError(t, err)
			require.Empty(t, changes.New)
			require.Empty(t, changes.Resolved)
			require.Len(t, changes.Unchanged, 1)
			require.Equal(t, "2.0", changes.Unchanged[0].Version)
			require.Zero(t, NewVulnerabilitiesAtOrAbove(changes, "High"))
		})
	}
}

func TestVulnerabilityDiffKeepsPackageQualifiers(t *testing.T) {
	for _, purls := range [][2]string{
		{"pkg:deb/debian/parser@1.0?arch=amd64", "pkg:deb/debian/parser@1.0?arch=arm64"},
		{"pkg:deb/debian/parser@1.0?distro=debian-11", "pkg:deb/debian/parser@1.0?distro=debian-12"},
		{"pkg:npm/%40first/parser@1.0", "pkg:npm/%40second/parser@1.0"},
		{"pkg:maven/org.first/parser@1.0#first", "pkg:maven/org.first/parser@1.0#second"},
	} {
		t.Run(purls[0], func(t *testing.T) {
			changes, err := ComputeVulnerabilities(
				writeJSONReport(t, packageDiffDocument(purls[0], "1.0")),
				writeJSONReport(t, packageDiffDocument(purls[1], "1.0")),
			)
			require.NoError(t, err)
			require.Len(t, changes.New, 1)
			require.Len(t, changes.Resolved, 1)
			require.Empty(t, changes.Unchanged)
		})
	}
}

func TestVulnerabilityDiffCanonicalizesPURLQualifierOrder(t *testing.T) {
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, packageDiffDocument("pkg:deb/debian/parser@1.0?arch=amd64&distro=debian", "1.0")),
		writeJSONReport(t, packageDiffDocument("pkg:deb/debian/parser@2.0?distro=debian&arch=amd64", "2.0")),
	)
	require.NoError(t, err)
	require.Empty(t, changes.New)
	require.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
}

func TestVulnerabilityDiffKnownAndLegacyIdentityDoNotMerge(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		base := packageDiffDocument("", "1.0")
		head := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
		if reverse {
			base, head = head, base
		}
		changes, err := ComputeVulnerabilities(writeJSONReport(t, base), writeJSONReport(t, head))
		require.NoError(t, err)
		require.Len(t, changes.New, 1)
		require.Len(t, changes.Resolved, 1)
		require.Empty(t, changes.Unchanged, "do not guess an absent ecosystem namespace")
	}
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, packageDiffDocument("", "1.0")),
		writeJSONReport(t, packageDiffDocument("", "2.0")),
	)
	require.NoError(t, err)
	require.Empty(t, changes.New)
	require.Len(t, changes.Unchanged, 1, "old reports without PURLs keep their original behavior")
}

func TestVulnerabilityDiffMalformedPURLFailsClosed(t *testing.T) {
	for _, purl := range []string{"not-a-purl", "pkg:", "pkg:maven/", "pkg:/missing-type"} {
		t.Run(purl, func(t *testing.T) {
			valid := writeJSONReport(t, packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0"))
			invalid := writeJSONReport(t, packageDiffDocument(purl, "1.0"))
			for _, paths := range [][2]string{{valid, invalid}, {invalid, valid}} {
				changes, err := ComputeVulnerabilities(paths[0], paths[1])
				require.Error(t, err)
				require.Nil(t, changes)
				require.Contains(t, err.Error(), "document 0, match 0")
				require.Contains(t, err.Error(), "purl")
				require.Contains(t, err.Error(), invalid)
			}
		})
	}
}

func TestVulnerabilityDiffPURLStructuredOutput(t *testing.T) {
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")),
		writeJSONReport(t, packageDiffDocument("pkg:maven/org.second/parser@2.0", "2.0")),
	)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, PrintVulnerabilityJSON(&output, changes))
	require.Contains(t, output.String(), `"purl": "pkg:maven/org.first/parser@1.0"`)
	require.Contains(t, output.String(), `"purl": "pkg:maven/org.second/parser@2.0"`)
	output.Reset()
	require.NoError(t, PrintVulnerabilityYAML(&output, changes))
	require.Contains(t, output.String(), "purl: pkg:maven/org.first/parser@1.0")
	require.Contains(t, output.String(), "purl: pkg:maven/org.second/parser@2.0")
}

func TestVulnerabilityDiffPURLDoesNotJoinDifferentCVEs(t *testing.T) {
	base := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	head := packageDiffDocument("pkg:maven/org.first/parser@2.0", "2.0")
	head["matches"].([]any)[0].(map[string]any)["vulnerability"].(map[string]any)["id"] = "CVE-2026-2000"
	changes, err := ComputeVulnerabilities(writeJSONReport(t, base), writeJSONReport(t, head))
	require.NoError(t, err)
	require.Len(t, changes.New, 1)
	require.Len(t, changes.Resolved, 1)
	require.Empty(t, changes.Unchanged)
	require.Equal(t, "CVE-2026-2000", changes.New[0].ID)
	require.Equal(t, "CVE-2026-1000", changes.Resolved[0].ID)
}

func TestVulnerabilityDiffPURLSortIsStableAcrossDocumentOrder(t *testing.T) {
	first := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	second := packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0")
	var expected string
	for _, documents := range [][]any{{first, second}, {second, first}} {
		changes, err := ComputeVulnerabilities(
			writeJSONReport(t, imageDocument("empty:1")), writeJSONReport(t, documents),
		)
		require.NoError(t, err)
		raw, err := json.Marshal(changes.New)
		require.NoError(t, err)
		if expected != "" {
			require.Equal(t, expected, string(raw))
		}
		expected = string(raw)
	}
}

func TestVulnerabilityDiffPURLRemovalDoesNotResolveOtherNamespace(t *testing.T) {
	first := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	second := packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0")
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, []any{first, second}), writeJSONReport(t, second),
	)
	require.NoError(t, err)
	require.Empty(t, changes.New)
	require.Len(t, changes.Resolved, 1)
	require.Len(t, changes.Unchanged, 1)
	var resolved bytes.Buffer
	require.NoError(t, PrintVulnerabilityPretty(&resolved, changes))
	require.Contains(t, resolved.String(), "pkg:maven/org.first/parser@1.0")
	require.NotContains(t, resolved.String(), "pkg:maven/org.second/parser@1.0")
}

func TestVulnerabilityDiffPURLKeepsUnknownSeverityGate(t *testing.T) {
	base := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	head := packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0")
	head["matches"].([]any)[0].(map[string]any)["vulnerability"].(map[string]any)["severity"] = "Unknown"
	changes, err := ComputeVulnerabilities(writeJSONReport(t, base), writeJSONReport(t, head))
	require.NoError(t, err)
	require.Len(t, changes.New, 1)
	require.Equal(t, "Unknown", changes.New[0].Severity)
	require.Equal(t, 1, NewVulnerabilitiesAtOrAbove(changes, "Critical"))
}

func TestVulnerabilityDiffPURLDoesNotReplaceArtifactType(t *testing.T) {
	base := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	head := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	head["matches"].([]any)[0].(map[string]any)["artifact"].(map[string]any)["type"] = "npm"
	changes, err := ComputeVulnerabilities(writeJSONReport(t, base), writeJSONReport(t, head))
	require.NoError(t, err)
	require.Len(t, changes.New, 1)
	require.Len(t, changes.Resolved, 1)
	require.Empty(t, changes.Unchanged)
}

func TestVulnerabilityDiffLegacyOutputOmitsUnavailablePURL(t *testing.T) {
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, imageDocument("empty:1")),
		writeJSONReport(t, packageDiffDocument("", "1.0")),
	)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, PrintVulnerabilityJSON(&output, changes))
	require.NotContains(t, output.String(), `"purl"`)
	output.Reset()
	require.NoError(t, PrintVulnerabilityPretty(&output, changes))
	require.Contains(t, output.String(), "parser 1.0")
	require.NotContains(t, output.String(), "pkg:")
}

func TestVersionlessPackageURLKeepsAnUnversionedPackage(t *testing.T) {
	got, err := versionlessPackageURL("pkg:maven/org.first/parser")
	require.NoError(t, err)
	require.Equal(t, "pkg:maven/org.first/parser", got)
}

func TestVulnerabilityDiffSameNamePackagesSurviveMultiImageUnion(t *testing.T) {
	first := packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0")
	second := packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0")
	for _, documents := range [][]any{{first, second, first}, {second, first, second}} {
		changes, err := ComputeVulnerabilities(
			writeJSONReport(t, imageDocument("empty:1")), writeJSONReport(t, documents),
		)
		require.NoError(t, err)
		require.Len(t, changes.New, 2)
		require.Empty(t, changes.Resolved)
		require.Equal(t, 2, NewVulnerabilitiesAtOrAbove(changes, "High"))
		var output bytes.Buffer
		require.NoError(t, PrintVulnerabilityJSON(&output, changes))
		var decoded struct {
			New []struct {
				PURL string `json:"purl"`
			} `json:"new"`
		}
		require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
		require.Equal(t, "pkg:maven/org.first/parser@1.0", decoded.New[0].PURL)
		require.Equal(t, "pkg:maven/org.second/parser@1.0", decoded.New[1].PURL)
	}
}

func TestVulnerabilityDiffPrettyIdentifiesSameNamePackages(t *testing.T) {
	changes, err := ComputeVulnerabilities(
		writeJSONReport(t, imageDocument("empty:1")),
		writeJSONReport(t, []any{
			packageDiffDocument("pkg:maven/org.second/parser@1.0", "1.0"),
			packageDiffDocument("pkg:maven/org.first/parser@1.0", "1.0"),
		}),
	)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, PrintVulnerabilityPretty(&output, changes))
	require.Contains(t, output.String(), "pkg:maven/org.first/parser@1.0")
	require.Contains(t, output.String(), "pkg:maven/org.second/parser@1.0")
	require.Equal(t, 2, strings.Count(output.String(), "[High]"))
}
