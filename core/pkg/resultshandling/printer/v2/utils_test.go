package printer

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func minimalPostureReport() *reporthandlingv2.PostureReport {
	return &reporthandlingv2.PostureReport{}
}

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name    string
		matches match.Matches
		image   string
		want    []imageprinter.CVE
	}{
		{
			name: "single vuln",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							ID:       "CVE-2020-1234",
							Severity: "High",
						},
						Fix: vulnerability.Fix{
							Versions: []string{"1.2.3"},
							State:    "Fixed",
						},
					},
				},
			}...),
			image: "nginx:latest",
			want: []imageprinter.CVE{
				{
					ID:          "CVE-2020-1234",
					Severity:    "High",
					Package:     "foo",
					Version:     "1.2.3",
					FixVersions: []string{"1.2.3"},
					FixedState:  "Fixed",
					Image:       "nginx:latest",
				},
			},
		},
		{
			name: "multiple vulns",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							ID:       "CVE-2020-1234",
							Severity: "High",
						},
						Fix: vulnerability.Fix{
							Versions: []string{"1.2.3"},
							State:    "Fixed",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "2",
						Name:    "test",
						Version: "1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							ID:       "CVE-2020-1235",
							Severity: "Critical",
						},
						Fix: vulnerability.Fix{
							Versions: []string{"1"},
							State:    "Fixed",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "3",
						Name:    "test2",
						Version: "3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							ID:       "CVE-2020-1236",
							Severity: "Low",
						},
						Fix: vulnerability.Fix{
							Versions: []string{"2", "3", "4"},
							State:    "Not fixed",
						},
					},
				},
			}...),
			image: "golang:1.24.6",
			want: []imageprinter.CVE{
				{
					ID:          "CVE-2020-1234",
					Severity:    "High",
					Package:     "foo",
					Version:     "1.2.3",
					FixVersions: []string{"1.2.3"},
					FixedState:  "Fixed",
					Image:       "golang:1.24.6",
				},
				{
					ID:          "CVE-2020-1235",
					Severity:    "Critical",
					Package:     "test",
					Version:     "1",
					FixVersions: []string{"1"},
					FixedState:  "Fixed",
					Image:       "golang:1.24.6",
				},
				{
					ID:          "CVE-2020-1236",
					Severity:    "Low",
					Package:     "test2",
					Version:     "3",
					FixVersions: []string{"2", "3", "4"},
					FixedState:  "Not fixed",
					Image:       "golang:1.24.6",
				},
			},
		},
		{
			name:    "empty vulns",
			matches: match.NewMatches([]match.Match{}...),
			image:   "test:latest",
			want:    []imageprinter.CVE{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractCVEs(tt.matches, tt.image, nil)
			if len(actual) != len(tt.want) {
				t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
			}
			for i := range actual {
				if actual[i].ID != tt.want[i].ID {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				if actual[i].Severity != tt.want[i].Severity {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				if actual[i].Package != tt.want[i].Package {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				if actual[i].Version != tt.want[i].Version {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				if actual[i].FixedState != tt.want[i].FixedState {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				if len(actual[i].FixVersions) != len(tt.want[i].FixVersions) {
					t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
				}
				for j := range actual[i].FixVersions {
					if actual[i].FixVersions[j] != tt.want[i].FixVersions[j] {
						t.Errorf("extractCVEs() = %v, want %v", actual, tt.want)
					}
				}
				if actual[i].Image != tt.want[i].Image {
					t.Errorf("extractCVEs() image = %v, want %v", actual[i].Image, tt.want[i].Image)
				}
			}
		})
	}

}

func TestExtractCVEsAddsMatchingVEXStatus(t *testing.T) {
	matches := match.NewMatches(match.Match{
		Package: pkg.Package{
			ID:      "1",
			Name:    "openssl",
			Version: "1.0.0",
		},
		Vulnerability: vulnerability.Vulnerability{
			Metadata: &vulnerability.Metadata{
				ID:       "CVE-2026-1234",
				Severity: "High",
			},
			Fix: vulnerability.Fix{
				State: vulnerability.FixStateNotFixed,
			},
		},
	})
	vexStatuses := map[string]cautils.VexStatus{
		"CVE-2026-1234": {
			Status:        "not_affected",
			Justification: "component_not_present",
		},
		"CVE-2026-9999": {
			Status:        "fixed",
			Justification: "inline_mitigations_already_exist",
		},
	}

	got := extractCVEs(matches, "registry.example.com/app:v1", vexStatuses)

	require.Len(t, got, 1)
	assert.Equal(t, "CVE-2026-1234", got[0].ID)
	assert.Equal(t, "not_affected", got[0].VexStatus)
	assert.Equal(t, "component_not_present", got[0].VexJustification)
}

func TestExtractCVEsLeavesUnmatchedVEXEmpty(t *testing.T) {
	matches := match.NewMatches(match.Match{
		Package: pkg.Package{
			ID:      "1",
			Name:    "openssl",
			Version: "1.0.0",
		},
		Vulnerability: vulnerability.Vulnerability{
			Metadata: &vulnerability.Metadata{
				ID:       "CVE-2026-1234",
				Severity: "High",
			},
		},
	})

	got := extractCVEs(matches, "registry.example.com/app:v1", map[string]cautils.VexStatus{
		"CVE-2026-9999": {
			Status:        "not_affected",
			Justification: "component_not_present",
		},
	})

	require.Len(t, got, 1)
	assert.Empty(t, got[0].VexStatus)
	assert.Empty(t, got[0].VexJustification)
}

func TestSetPkgNameToScoreMap(t *testing.T) {
	tests := []struct {
		name        string
		matches     match.Matches
		originalMap map[string]*imageprinter.PackageScore
		want        map[string]*imageprinter.PackageScore
	}{
		{
			name: "single package",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
			}...),
			want: map[string]*imageprinter.PackageScore{
				"foo@1.2.3": {
					Name:    "foo",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
		},
		{
			name: "multiple packages - different versions",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Critical",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "2",
						Name:    "pkg2",
						Version: "1.2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Low",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "3",
						Name:    "pkg3",
						Version: "1.2.3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
			}...),
			want: map[string]*imageprinter.PackageScore{
				"pkg1@version1": {
					Name:    "pkg1",
					Score:   5,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
				"pkg2@1.2": {
					Name:    "pkg2",
					Score:   2,
					Version: "1.2",
					MapSeverityToCVEsNumber: map[string]int{
						"Low": 1,
					},
				},
				"pkg3@1.2.3": {
					Name:    "pkg3",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
		},
		{
			name: "multiple packages - mixed versions",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "2",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "3",
						Name:    "pkg1",
						Version: "version2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Critical",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "4",
						Name:    "pkg3",
						Version: "1.2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Medium",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "5",
						Name:    "pkg3",
						Version: "1.2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Low",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "6",
						Name:    "pkg4",
						Version: "1.2.3",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
			}...),
			want: map[string]*imageprinter.PackageScore{
				"pkg1@version1": {
					Name:    "pkg1",
					Score:   8,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 2,
					},
				},
				"pkg1@version2": {
					Name:    "pkg1",
					Score:   5,
					Version: "version2",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
				"pkg3@1.2": {
					Name:    "pkg3",
					Score:   5,
					Version: "1.2",
					MapSeverityToCVEsNumber: map[string]int{
						"Medium": 1,
						"Low":    1,
					},
				},
				"pkg4@1.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
		},
		{
			name:    "empty packages",
			matches: match.NewMatches(),
			want:    map[string]*imageprinter.PackageScore{},
		},
		{
			name: "original map not empty",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "pkg1",
						Version: "version2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Critical",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "2",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "3",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
			}...),
			originalMap: map[string]*imageprinter.PackageScore{
				"pkg4@1.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg4@1.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
				"pkg1@version1": {
					Name:    "pkg1",
					Score:   8,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 2,
					},
				},
				"pkg1@version2": {
					Name:    "pkg1",
					Score:   5,
					Version: "version2",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
			},
		},
		{
			name: "original map with same package",
			matches: match.NewMatches([]match.Match{
				{
					Package: pkg.Package{
						ID:      "1",
						Name:    "pkg1",
						Version: "version2",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "Critical",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "2",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
				{
					Package: pkg.Package{
						ID:      "3",
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: vulnerability.Vulnerability{
						Metadata: &vulnerability.Metadata{
							Severity: "High",
						},
					},
				},
			}...),
			originalMap: map[string]*imageprinter.PackageScore{
				"pkg1@version1": {
					Name:    "pkg1",
					Score:   4,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg1@version1": {
					Name:    "pkg1",
					Score:   12,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 3,
					},
				},
				"pkg1@version2": {
					Name:    "pkg1",
					Score:   5,
					Version: "version2",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.originalMap == nil {
				tt.originalMap = make(map[string]*imageprinter.PackageScore)
			}

			setPkgNameToScoreMap(tt.matches, tt.originalMap)
			if len(tt.originalMap) == 0 {
				assert.Equal(t, tt.want, tt.originalMap)
				return
			}

			if len(tt.originalMap) != len(tt.want) {
				t.Errorf("%s failed for length, got = %v, want %v", tt.name, len(tt.originalMap), len(tt.want))
			}

			for k := range tt.originalMap {
				if tt.originalMap[k].Score != tt.want[k].Score {
					t.Errorf("%s failed for score, got = %v, want %v", tt.name, tt.want[k].Score, tt.originalMap[k].Score)
				}
				if tt.originalMap[k].Version != tt.want[k].Version {
					t.Errorf("%s failed for version, got = %v, want %v", tt.name, tt.want[k].Version, tt.originalMap[k].Version)

				}
				if tt.originalMap[k].Name != tt.want[k].Name {
					t.Errorf("%s failed for name, got = %v, want %v", tt.name, tt.want[k].Name, tt.originalMap[k].Name)
				}

				for s := range tt.originalMap[k].MapSeverityToCVEsNumber {
					if tt.originalMap[k].MapSeverityToCVEsNumber[s] != tt.want[k].MapSeverityToCVEsNumber[s] {
						t.Errorf("%s failed for severity %s, got = %v, want %v", tt.name, s, tt.want[k].MapSeverityToCVEsNumber[s], tt.originalMap[k].MapSeverityToCVEsNumber[s])
					}
				}
			}
		})
	}
}

// TestSetPkgNameToScoreMap_NoCollisionWithoutSeparator verifies that two
// distinct (name, version) pairs whose concatenation would be identical if no
// separator were used between them - e.g. name="foo1"+version="2.3" and
// name="foo"+version="12.3", both "foo12.3" - are kept as separate entries
// instead of one silently overwriting the other's CVE data.
func TestSetPkgNameToScoreMap_NoCollisionWithoutSeparator(t *testing.T) {
	matches := match.NewMatches([]match.Match{
		{
			Package: pkg.Package{
				ID:      "1",
				Name:    "foo1",
				Version: "2.3",
			},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{
					Severity: "High",
				},
			},
		},
		{
			Package: pkg.Package{
				ID:      "2",
				Name:    "foo",
				Version: "12.3",
			},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{
					Severity: "Critical",
				},
			},
		},
	}...)

	pkgScores := make(map[string]*imageprinter.PackageScore)
	setPkgNameToScoreMap(matches, pkgScores)

	require.Len(t, pkgScores, 2, "both packages must have their own entry, not collide into one")

	names := make(map[string]string)
	for _, score := range pkgScores {
		names[score.Name+"/"+score.Version] = score.Name
	}
	assert.Contains(t, names, "foo1/2.3")
	assert.Contains(t, names, "foo/12.3")
}

// TestSetPkgNameToScoreMap_NoCollisionWithAtInNameOrVersion verifies that
// the "@" delimiter itself does not reintroduce the collision class it was
// meant to fix. Package names can legitimately contain "@" (e.g. npm scoped
// packages such as "@angular/core"), so without escaping, name="foo@bar"
// + version="baz" and name="foo" + version="bar@baz" would both join to the
// same raw string "foo@bar@baz" and collide.
func TestSetPkgNameToScoreMap_NoCollisionWithAtInNameOrVersion(t *testing.T) {
	matches := match.NewMatches([]match.Match{
		{
			Package: pkg.Package{
				ID:      "1",
				Name:    "foo@bar",
				Version: "baz",
			},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{
					Severity: "High",
				},
			},
		},
		{
			Package: pkg.Package{
				ID:      "2",
				Name:    "foo",
				Version: "bar@baz",
			},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{
					Severity: "Critical",
				},
			},
		},
	}...)

	pkgScores := make(map[string]*imageprinter.PackageScore)
	setPkgNameToScoreMap(matches, pkgScores)

	require.Len(t, pkgScores, 2, "both packages must have their own entry, not collide into one")

	names := make(map[string]string)
	for _, score := range pkgScores {
		names[score.Name+"/"+score.Version] = score.Name
	}
	assert.Contains(t, names, "foo@bar/baz")
	assert.Contains(t, names, "foo/bar@baz")
}

// TestPkgScoreKeyIsCollisionFree exercises pkgScoreKey directly against a
// broader set of adversarial (name, version) pairs - including values
// containing the delimiter and the escape character itself - and asserts
// every pair maps to a distinct key.
func TestPkgScoreKeyIsCollisionFree(t *testing.T) {
	type nameVersion struct{ name, version string }
	pairs := []nameVersion{
		{"foo1", "2.3"},
		{"foo", "12.3"},
		{"foo@bar", "baz"},
		{"foo", "bar@baz"},
		{"@angular/core", "12.3"},
		{"@angular/core@12", "3"},
		{`foo\`, "bar"},
		{"foo", `\bar`},
		{`foo\@`, "bar"},
		{"foo", `\@bar`},
	}

	seen := make(map[string]nameVersion)
	for _, p := range pairs {
		key := pkgScoreKey(p.name, p.version)
		if prev, ok := seen[key]; ok {
			t.Fatalf("key collision: (%q,%q) and (%q,%q) both produced key %q", prev.name, prev.version, p.name, p.version, key)
		}
		seen[key] = p
	}
}

func TestSetSeverityToSummaryMap(t *testing.T) {
	tests := []struct {
		name        string
		cves        []imageprinter.CVE
		originalMap map[string]*imageprinter.SeveritySummary
		want        map[string]*imageprinter.SeveritySummary
	}{
		{
			name: "single cve",
			cves: []imageprinter.CVE{
				{
					ID:         "CVE-2020-1234",
					Severity:   "High",
					FixedState: string(v5.FixedState),
				},
			},
			want: map[string]*imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 1,
				},
			},
		},
		{
			name: "multiple cves",
			cves: []imageprinter.CVE{
				{
					ID:         "CVE-2020-1234",
					Severity:   "High",
					FixedState: string(v5.FixedState),
				},
				{
					ID:         "CVE-2020-1235",
					Severity:   "High",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-23",
					Severity:   "Low",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-4321",
					Severity:   "Medium",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-53152",
					Severity:   "Negligible",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-531524",
					Severity:   "Negligible",
					FixedState: string(v5.NotFixedState),
				},
			},
			want: map[string]*imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        2,
					NumberOfFixableCVEs: 1,
				},
				"Low": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 0,
				},
				"Medium": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 0,
				},
				"Negligible": {
					NumberOfCVEs:        2,
					NumberOfFixableCVEs: 0,
				},
			},
		},
		{
			name: "multiple cves - non empty map",
			cves: []imageprinter.CVE{
				{
					ID:         "CVE-2020-1234",
					Severity:   "High",
					FixedState: string(v5.FixedState),
				},
				{
					ID:         "CVE-2020-1235",
					Severity:   "High",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-23",
					Severity:   "Low",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-4321",
					Severity:   "Medium",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-53152",
					Severity:   "Negligible",
					FixedState: string(v5.NotFixedState),
				},
				{
					ID:         "CVE-2020-531524",
					Severity:   "Negligible",
					FixedState: string(v5.NotFixedState),
				},
			},
			originalMap: map[string]*imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 1,
				},
				"Low": {
					NumberOfCVEs:        3,
					NumberOfFixableCVEs: 0,
				},
			},
			want: map[string]*imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        3,
					NumberOfFixableCVEs: 2,
				},
				"Low": {
					NumberOfCVEs:        4,
					NumberOfFixableCVEs: 0,
				},
				"Medium": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 0,
				},
				"Negligible": {
					NumberOfCVEs:        2,
					NumberOfFixableCVEs: 0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.originalMap == nil {
				tt.originalMap = make(map[string]*imageprinter.SeveritySummary)
			}

			setSeverityToSummaryMap(tt.cves, tt.originalMap)

			if len(tt.originalMap) != len(tt.want) {
				t.Errorf("%s failed for length, got = %v, want %v", tt.name, len(tt.originalMap), len(tt.want))
			}

			for k := range tt.originalMap {
				if tt.originalMap[k].NumberOfCVEs != tt.want[k].NumberOfCVEs {
					t.Errorf("%s failed for CVEs number, got = %v, want %v", tt.name, tt.originalMap[k].NumberOfCVEs, tt.want[k].NumberOfCVEs)
				}
				if tt.originalMap[k].NumberOfFixableCVEs != tt.want[k].NumberOfFixableCVEs {
					t.Errorf("%s failed for fixable CVEs number, got = %v, want %v", tt.name, tt.originalMap[k].NumberOfFixableCVEs, tt.want[k].NumberOfFixableCVEs)
				}
			}
		})
	}
}

func createWorkloadWithLabels(name, namespace string, labels map[string]string) workloadinterface.IMetadata {
	// Convert labels to map[string]interface{} for JSON marshaling
	labelsInterface := make(map[string]any)
	for k, v := range labels {
		labelsInterface[k] = v
	}

	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels":    labelsInterface,
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{},
				},
			},
		},
	}
	objBytes, _ := json.Marshal(obj)
	workload, _ := workloadinterface.NewWorkload(objBytes)
	return workload
}

func TestExtractResourceLabels(t *testing.T) {
	tests := []struct {
		name         string
		allResources map[string]workloadinterface.IMetadata
		labelsToCopy []string
		want         map[string]map[string]string
	}{
		{
			name:         "empty resources",
			allResources: map[string]workloadinterface.IMetadata{},
			labelsToCopy: []string{"app", "team"},
			want:         map[string]map[string]string{},
		},
		{
			name:         "empty labels to copy",
			allResources: map[string]workloadinterface.IMetadata{},
			labelsToCopy: []string{},
			want:         map[string]map[string]string{},
		},
		{
			name: "single resource with matching labels",
			allResources: map[string]workloadinterface.IMetadata{
				"resource-1": createWorkloadWithLabels("test-deploy", "default", map[string]string{
					"app":     "myapp",
					"team":    "platform",
					"version": "v1",
				}),
			},
			labelsToCopy: []string{"app", "team"},
			want: map[string]map[string]string{
				"resource-1": {
					"app":  "myapp",
					"team": "platform",
				},
			},
		},
		{
			name: "single resource with partial matching labels",
			allResources: map[string]workloadinterface.IMetadata{
				"resource-1": createWorkloadWithLabels("test-deploy", "default", map[string]string{
					"app": "myapp",
				}),
			},
			labelsToCopy: []string{"app", "team"},
			want: map[string]map[string]string{
				"resource-1": {
					"app": "myapp",
				},
			},
		},
		{
			name: "single resource with no matching labels",
			allResources: map[string]workloadinterface.IMetadata{
				"resource-1": createWorkloadWithLabels("test-deploy", "default", map[string]string{
					"version": "v1",
				}),
			},
			labelsToCopy: []string{"app", "team"},
			want:         map[string]map[string]string{},
		},
		{
			name: "multiple resources with various labels",
			allResources: map[string]workloadinterface.IMetadata{
				"resource-1": createWorkloadWithLabels("deploy-1", "default", map[string]string{
					"app":  "app1",
					"team": "team1",
				}),
				"resource-2": createWorkloadWithLabels("deploy-2", "default", map[string]string{
					"app": "app2",
				}),
				"resource-3": createWorkloadWithLabels("deploy-3", "default", map[string]string{
					"version": "v1",
				}),
			},
			labelsToCopy: []string{"app", "team"},
			want: map[string]map[string]string{
				"resource-1": {
					"app":  "app1",
					"team": "team1",
				},
				"resource-2": {
					"app": "app2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResourceLabels(tt.allResources, tt.labelsToCopy)
			assert.Equal(t, len(tt.want), len(got), "number of resources with extracted labels should match")
			for resourceID, wantLabels := range tt.want {
				gotLabels, ok := got[resourceID]
				assert.True(t, ok, "resource %s should be present in result", resourceID)
				assert.Equal(t, wantLabels, gotLabels, "labels for resource %s should match", resourceID)
			}
		})
	}
}

// TestConvertToPostureReport_PartialOnlyCoverageAttached verifies that a
// ScanCoverage containing only PartialGVRPulls (no whole-GVR failures, no
// NotEvaluatedControls) is still attached to the serialized report. Prior to
// the fix, the guard only checked FailedGVRPulls and NotEvaluatedControls, so
// a partial-only scan would produce a JSON/API response with no scanCoverage
// field at all — hiding the incomplete-data condition from consumers.
func TestConvertToPostureReport_PartialOnlyCoverageAttached(t *testing.T) {
	coverage := &cautils.ScanCoverage{
		PartialGVRPulls: []cautils.PartialGVRPull{
			{GVR: "/v1/pods", Selector: "metadata.namespace=prod", Error: "forbidden for prod"},
		},
	}

	result := ConvertToPostureReportWithSeverityLabelsAndCoverage(nil, nil, nil, coverage)
	require.Nil(t, result, "nil report should return nil")

	// Use a minimal non-nil report so we can inspect the ScanCoverage field.
	result = ConvertToPostureReportWithSeverityLabelsAndCoverage(
		minimalPostureReport(),
		nil, nil, coverage,
	)
	require.NotNil(t, result)
	require.NotNil(t, result.ScanCoverage, "ScanCoverage must be attached when PartialGVRPulls is non-empty")
	assert.Len(t, result.ScanCoverage.PartialGVRPulls, 1)
	assert.Equal(t, "/v1/pods", result.ScanCoverage.PartialGVRPulls[0].GVR)
}

// TestConvertToPostureReport_NilCoverageNotAttached verifies that a nil
// coverage pointer (clean scan) produces a nil ScanCoverage in the output.
func TestConvertToPostureReport_NilCoverageNotAttached(t *testing.T) {
	result := ConvertToPostureReportWithSeverityLabelsAndCoverage(
		minimalPostureReport(),
		nil, nil, nil,
	)
	require.NotNil(t, result)
	assert.Nil(t, result.ScanCoverage)
}

// TestConvertToPostureReport_VacuousFrameworksOnlyCoverageAttached verifies
// that a ScanCoverage containing only VacuousFrameworks (no GVR pull
// failures, no NotEvaluatedControls) is still attached to the serialized
// report, so a framework that scored 100% purely because its target
// resource types are absent from the cluster is visible to JSON/API
// consumers.
func TestConvertToPostureReport_VacuousFrameworksOnlyCoverageAttached(t *testing.T) {
	coverage := &cautils.ScanCoverage{
		VacuousFrameworks: []string{"istio-security"},
	}

	result := ConvertToPostureReportWithSeverityLabelsAndCoverage(
		minimalPostureReport(),
		nil, nil, coverage,
	)
	require.NotNil(t, result)
	require.NotNil(t, result.ScanCoverage, "ScanCoverage must be attached when VacuousFrameworks is non-empty")
	assert.Equal(t, []string{"istio-security"}, result.ScanCoverage.VacuousFrameworks)

	raw, err := json.Marshal(result)
	require.NoError(t, err)
	var decoded struct {
		ScanCoverage struct {
			VacuousFrameworks []string `json:"vacuousFrameworks"`
		} `json:"scanCoverage"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, []string{"istio-security"}, decoded.ScanCoverage.VacuousFrameworks)
}

// TestFinalizeResults_SetsGenerationTimeWhenZero is the regression test for
// kubescape/kubescape#2325: JSON reports were emitting
// "generationTime":"0001-01-01T00:00:00Z" because nothing on the scan path
// ever assigned ReportGenerationTime. FinalizeResults is the single funnel
// for both file output and SaaS submission, so the fix lives there.
func TestFinalizeResults_SetsGenerationTimeWhenZero(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	require.True(t, session.Report.ReportGenerationTime.IsZero(),
		"precondition: mock starts with the zero-value time that #2325 reported")

	before := time.Now().UTC()
	report := FinalizeResults(session)
	after := time.Now().UTC()

	require.NotNil(t, report)
	assert.False(t, report.ReportGenerationTime.IsZero(),
		"FinalizeResults must populate ReportGenerationTime")
	assert.False(t, session.Report.ReportGenerationTime.IsZero(),
		"FinalizeResults must also write back to the session so downstream consumers see it")
	assert.Equal(t, session.Report.ReportGenerationTime, report.ReportGenerationTime)
	assert.WithinDuration(t, before, report.ReportGenerationTime, after.Sub(before)+time.Second)
}

// TestFinalizeResults_PreservesExistingGenerationTime ensures we don't clobber
// a timestamp that the caller has already set (e.g. when callers eventually
// thread a real scan-start time through Scan(...)).
func TestFinalizeResults_PreservesExistingGenerationTime(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	preset := time.Date(2024, 3, 14, 9, 15, 26, 0, time.UTC)
	session.Report.ReportGenerationTime = preset

	report := FinalizeResults(session)

	require.NotNil(t, report)
	assert.Equal(t, preset, report.ReportGenerationTime)
	assert.Equal(t, preset, session.Report.ReportGenerationTime)
}

func TestFinalizeResults_SetsReportIDFromSession(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.SessionID = "scan-6f012842"
	require.Empty(t, session.Report.ReportID,
		"precondition: the report has not been assigned an ID")

	report := FinalizeResults(session)

	require.NotNil(t, report)
	assert.Equal(t, "scan-6f012842", report.ReportID)
	assert.Equal(t, "scan-6f012842", session.Report.ReportID,
		"FinalizeResults must write the ID back so every downstream consumer observes the same identity")
}

func TestFinalizeResults_PreservesExistingReportID(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.SessionID = "scan-new"
	session.Report.ReportID = "report-preset"

	report := FinalizeResults(session)

	require.NotNil(t, report)
	assert.Equal(t, "report-preset", report.ReportID)
	assert.Equal(t, "report-preset", session.Report.ReportID)
}

// TestFinalizeResults_SetsClusterNameWhenEmpty is the regression test for
// kubescape/kubescape#2856: JSON reports always had an empty clusterName
// because nothing on the scan path ever assigned OPASessionObj.Report.ClusterName,
// even though the context name is known via k8sinterface at scan time.
func TestFinalizeResults_SetsClusterNameWhenEmpty(t *testing.T) {
	k8sinterface.SetClusterContextName("test-cluster")
	defer k8sinterface.SetClusterContextName("")

	session := cautils.NewOPASessionObjMock()
	require.Empty(t, session.Report.ClusterName,
		"precondition: mock starts with the empty ClusterName that #2856 reported")

	report := FinalizeResults(session)

	require.NotNil(t, report)
	assert.Equal(t, "test-cluster", report.ClusterName)
	assert.Equal(t, "test-cluster", session.Report.ClusterName,
		"FinalizeResults must also write back to the session so downstream consumers see it")
}

// TestFinalizeResults_PreservesExistingClusterName ensures we don't clobber a
// cluster name the caller has already set.
func TestFinalizeResults_PreservesExistingClusterName(t *testing.T) {
	k8sinterface.SetClusterContextName("other-cluster")
	defer k8sinterface.SetClusterContextName("")

	session := cautils.NewOPASessionObjMock()
	session.Report.ClusterName = "preset-cluster"

	report := FinalizeResults(session)

	require.NotNil(t, report)
	assert.Equal(t, "preset-cluster", report.ClusterName)
	assert.Equal(t, "preset-cluster", session.Report.ClusterName)
}

func TestFinalizeResults_SortsResultsAndResourcesByResourceID(t *testing.T) {
	session := cautils.NewOPASessionObjMock()

	resources := []workloadinterface.IMetadata{
		createWorkloadWithLabels("zeta", "default", nil),
		createWorkloadWithLabels("alpha", "default", nil),
		createWorkloadWithLabels("kappa", "default", nil),
		createWorkloadWithLabels("beta", "default", nil),
		createWorkloadWithLabels("theta", "default", nil),
		createWorkloadWithLabels("delta", "default", nil),
		createWorkloadWithLabels("eta", "default", nil),
		createWorkloadWithLabels("gamma", "default", nil),
	}
	expectedResourceIDs := make([]string, 0, len(resources))

	// Insert resources in a deliberately non-canonical order. FinalizeResults
	// must define its own stable order instead of exposing Go map iteration.
	for _, resource := range resources {
		resourceID := resource.GetID()
		expectedResourceIDs = append(expectedResourceIDs, resourceID)
		session.ResourcesResult[resourceID] = resourcesresults.Result{ResourceID: resourceID}
		session.AllResources[resourceID] = resource
	}
	sort.Strings(expectedResourceIDs)

	for i := 0; i < 64; i++ {
		report := FinalizeResults(session)
		require.NotNil(t, report)
		require.Len(t, report.Results, len(expectedResourceIDs))
		require.Len(t, report.Resources, len(expectedResourceIDs))

		resultResourceIDs := make([]string, 0, len(report.Results))
		for _, result := range report.Results {
			resultResourceIDs = append(resultResourceIDs, result.ResourceID)
		}
		require.Equalf(t, expectedResourceIDs, resultResourceIDs, "results iteration %d", i)

		resourceIDs := make([]string, 0, len(report.Resources))
		for _, resource := range report.Resources {
			resourceIDs = append(resourceIDs, resource.ResourceID)
		}
		require.Equalf(t, expectedResourceIDs, resourceIDs, "resources iteration %d", i)
	}
}

func Test_mapInfoToPrintInfo_stableMarkers(t *testing.T) {
	skipReasons := map[string]string{
		"C-0001": "no cluster connection",
		"C-0002": "host scanner is not deployed",
		"C-0003": "control configuration is missing",
		"C-0004": "resource kind was not scanned",
	}

	controls := reportsummary.ControlSummaries{}
	for controlID, info := range skipReasons {
		controls[controlID] = reportsummary.ControlSummary{
			ControlID:  controlID,
			StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, InnerInfo: info},
		}
	}

	want := []infoStars{
		{stars: "†", info: skipReasons["C-0001"]},
		{stars: "††", info: skipReasons["C-0002"]},
		{stars: "†††", info: skipReasons["C-0003"]},
		{stars: "††††", info: skipReasons["C-0004"]},
	}

	// The PDF printer reads the markers for the table and the legend from
	// separate calls, so every call must return the same assignment.
	for i := 0; i < 64; i++ {
		require.Equalf(t, want, mapInfoToPrintInfo(controls), "iteration %d", i)
	}
}

func TestFilterBySeverity(t *testing.T) {
	report := &PostureReportWithSeverity{
		SummaryDetails: SummaryDetailsWithSeverity{
			Controls: map[string]ControlSummaryWithSeverity{
				"C-0001": {Severity: "Critical"},
				"C-0002": {Severity: "High"},
				"C-0003": {Severity: "Medium"},
				"C-0004": {Severity: "Low"},
			},
		},
		Results: []ResultWithSeverity{
			{
				ResourceID: "res-1",
				AssociatedControls: []ResourceAssociatedControlWithSeverity{
					{Severity: "Critical"},
					{Severity: "High"},
					{Severity: "Medium"},
					{Severity: "Low"},
				},
			},
		},
	}

	FilterBySeverity(report, "high")

	assert.Len(t, report.SummaryDetails.Controls, 2)
	assert.Contains(t, report.SummaryDetails.Controls, "C-0001")
	assert.Contains(t, report.SummaryDetails.Controls, "C-0002")
	assert.NotContains(t, report.SummaryDetails.Controls, "C-0003")

	assert.Len(t, report.Results[0].AssociatedControls, 2)
	for _, c := range report.Results[0].AssociatedControls {
		assert.Contains(t, []string{"Critical", "High"}, c.Severity)
	}
}

func TestFilterBySeverity_EmptyMinSeverityNoOp(t *testing.T) {
	report := &PostureReportWithSeverity{
		SummaryDetails: SummaryDetailsWithSeverity{
			Controls: map[string]ControlSummaryWithSeverity{
				"C-0001": {Severity: "Low"},
			},
		},
	}
	FilterBySeverity(report, "")
	assert.Len(t, report.SummaryDetails.Controls, 1)
}

func TestBuildMachineImageScanSummaryKeepsStableImageIdentity(t *testing.T) {
	data := []cautils.ImageScanData{
		{Image: "example/app:latest", Platform: "linux/amd64"},
		{Image: "example/app:latest", Platform: "linux/arm64"},
	}

	machine := buildMachineImageScanSummary(data)
	display := buildImageScanSummary(data)

	assert.Equal(t, []string{"example/app:latest"}, machine.Images)
	assert.Equal(t, []string{
		"example/app:latest [linux/amd64]",
		"example/app:latest [linux/arm64]",
	}, display.Images)
}

func TestBuildImageScanSummary_CarriesVulnDBBuilt(t *testing.T) {
	builtAt := time.Now().Add(-24 * time.Hour).Truncate(time.Second)

	imageData := []cautils.ImageScanData{
		{Image: "img:1", VulnDBBuilt: &builtAt},
		{Image: "img:2"}, // no built time; first non-nil wins
	}

	summary := buildImageScanSummary(imageData)

	require.NotNil(t, summary)
	assert.Equal(t, builtAt, *summary.VulnDBBuilt)
	assert.Equal(t, []string{"img:1", "img:2"}, summary.Images)
}

func TestBuildImageScanSummary_NilWhenNoBuilt(t *testing.T) {
	imageData := []cautils.ImageScanData{
		{Image: "img:1"},
	}

	summary := buildImageScanSummary(imageData)

	require.NotNil(t, summary)
	assert.Nil(t, summary.VulnDBBuilt)
}
