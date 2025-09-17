package printer

import (
	"testing"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/stretchr/testify/assert"
)

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name    string
		matches match.Matches
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
			want: []imageprinter.CVE{
				{
					ID:          "CVE-2020-1234",
					Severity:    "High",
					Package:     "foo",
					Version:     "1.2.3",
					FixVersions: []string{"1.2.3"},
					FixedState:  "Fixed",
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
			want: []imageprinter.CVE{
				{
					ID:          "CVE-2020-1234",
					Severity:    "High",
					Package:     "foo",
					Version:     "1.2.3",
					FixVersions: []string{"1.2.3"},
					FixedState:  "Fixed",
				},
				{
					ID:          "CVE-2020-1235",
					Severity:    "Critical",
					Package:     "test",
					Version:     "1",
					FixVersions: []string{"1"},
					FixedState:  "Fixed",
				},
				{
					ID:          "CVE-2020-1236",
					Severity:    "Low",
					Package:     "test2",
					Version:     "3",
					FixVersions: []string{"2", "3", "4"},
					FixedState:  "Not fixed",
				},
			},
		},
		{
			name:    "empty vulns",
			matches: match.NewMatches([]match.Match{}...),
			want:    []imageprinter.CVE{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractCVEs(tt.matches)
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
			}
		})
	}

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
				"foo1.2.3": {
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
				"pkg1version1": {
					Name:    "pkg1",
					Score:   5,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
				"pkg21.2": {
					Name:    "pkg2",
					Score:   2,
					Version: "1.2",
					MapSeverityToCVEsNumber: map[string]int{
						"Low": 1,
					},
				},
				"pkg31.2.3": {
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
				"pkg1version1": {
					Name:    "pkg1",
					Score:   8,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 2,
					},
				},
				"pkg1version2": {
					Name:    "pkg1",
					Score:   5,
					Version: "version2",
					MapSeverityToCVEsNumber: map[string]int{
						"Critical": 1,
					},
				},
				"pkg31.2": {
					Name:    "pkg3",
					Score:   5,
					Version: "1.2",
					MapSeverityToCVEsNumber: map[string]int{
						"Medium": 1,
						"Low":    1,
					},
				},
				"pkg41.2.3": {
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
				"pkg41.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg41.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
				"pkg1version1": {
					Name:    "pkg1",
					Score:   8,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 2,
					},
				},
				"pkg1version2": {
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
				"pkg1version1": {
					Name:    "pkg1",
					Score:   4,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 1,
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg1version1": {
					Name:    "pkg1",
					Score:   12,
					Version: "version1",
					MapSeverityToCVEsNumber: map[string]int{
						"High": 3,
					},
				},
				"pkg1version2": {
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
