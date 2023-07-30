package printer

import (
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/stretchr/testify/assert"
)

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name    string
		matches []models.Match
		want    []imageprinter.CVE
	}{
		{
			name: "single vuln",
			matches: []models.Match{
				{
					Artifact: models.Package{
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							ID:       "CVE-2020-1234",
							Severity: "High",
						},
						Fix: models.Fix{
							Versions: []string{"1.2.3"},
							State:    "Fixed",
						},
					},
				},
			},
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
			matches: []models.Match{
				{
					Artifact: models.Package{
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							ID:       "CVE-2020-1234",
							Severity: "High",
						},
						Fix: models.Fix{
							Versions: []string{"1.2.3"},
							State:    "Fixed",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "test",
						Version: "1",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							ID:       "CVE-2020-1235",
							Severity: "Critical",
						},
						Fix: models.Fix{
							Versions: []string{"1"},
							State:    "Fixed",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "test2",
						Version: "3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							ID:       "CVE-2020-1236",
							Severity: "Low",
						},
						Fix: models.Fix{
							Versions: []string{"2", "3", "4"},
							State:    "Not fixed",
						},
					},
				},
			},
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
			matches: []models.Match{},
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

func TestExtractPkgNameToScoreMap(t *testing.T) {
	tests := []struct {
		name    string
		matches []models.Match
		want    map[string]*imageprinter.PackageScore
	}{
		{
			name: "single package",
			matches: []models.Match{
				{
					Artifact: models.Package{
						Name:    "foo",
						Version: "1.2.3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "High",
						},
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"foo1.2.3": {
					Name:    "foo",
					Score:   4,
					Version: "1.2.3",
				},
			},
		},
		{
			name: "multiple packages - different versions",
			matches: []models.Match{
				{
					Artifact: models.Package{
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "Critical",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg2",
						Version: "1.2",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "Low",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg3",
						Version: "1.2.3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "High",
						},
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg1version1": {
					Name:    "pkg1",
					Score:   5,
					Version: "version1",
				},
				"pkg21.2": {
					Name:    "pkg2",
					Score:   2,
					Version: "1.2",
				},
				"pkg31.2.3": {
					Name:    "pkg3",
					Score:   4,
					Version: "1.2.3",
				},
			},
		},
		{
			name: "multiple packages - mixed versions",
			matches: []models.Match{
				{
					Artifact: models.Package{
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "High",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg1",
						Version: "version1",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "High",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg1",
						Version: "version2",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "Critical",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg3",
						Version: "1.2",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "Medium",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg3",
						Version: "1.2",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "Low",
						},
					},
				},
				{
					Artifact: models.Package{
						Name:    "pkg4",
						Version: "1.2.3",
					},
					Vulnerability: models.Vulnerability{
						VulnerabilityMetadata: models.VulnerabilityMetadata{
							Severity: "High",
						},
					},
				},
			},
			want: map[string]*imageprinter.PackageScore{
				"pkg1version1": {
					Name:    "pkg1",
					Score:   8,
					Version: "version1",
				},
				"pkg1version2": {
					Name:    "pkg1",
					Score:   5,
					Version: "version2",
				},
				"pkg31.2": {
					Name:    "pkg3",
					Score:   5,
					Version: "1.2",
				},
				"pkg41.2.3": {
					Name:    "pkg4",
					Score:   4,
					Version: "1.2.3",
				},
			},
		},
		{
			name:    "empty packages",
			matches: []models.Match{},
			want:    map[string]*imageprinter.PackageScore{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractPkgNameToScoreMap(tt.matches)
			if len(actual) == 0 {
				assert.Equal(t, tt.want, actual)
				return
			}

			if len(actual) != len(tt.want) {
				t.Errorf("extractPkgNameToScore() = %v, want %v", actual, tt.want)
			}

			for k := range actual {
				if actual[k].Score != tt.want[k].Score {
					t.Errorf("extractPkgNameToScore() = %v, want %v", actual, tt.want)
				}
				if actual[k].Version != tt.want[k].Version {
					t.Errorf("extractPkgNameToScore() = %v, want %v", actual, tt.want)
				}
				if actual[k].Name != tt.want[k].Name {
					t.Errorf("extractPkgNameToScore() = %v, want %v", actual, tt.want)
				}
			}
		})
	}
}

// func TestExtractSeverityToSummaryMap(t *testing.T) {
// 	tests := []struct {
// 		name string
// 		cves []imageprinter.CVE
// 		want map[string]*imageprinter.SeveritySummary
// 	}{
// 		{
// 			name: "single cve",
// 			cves: []imageprinter.CVE{
// 				{
// 					ID:         "CVE-2020-1234",
// 					Severity:   "High",
// 					FixedState: string(v5.FixedState),
// 				},
// 			},
// 			want: map[string]*imageprinter.SeveritySummary{
// 				"High": {
// 					NumberOfCVEs:        1,
// 					NumberOfFixableCVEs: 1,
// 				},
// 			},
// 		},
// 		{
// 			name: "multiple cves",
// 			cves: []imageprinter.CVE{
// 				{
// 					ID:         "CVE-2020-1234",
// 					Severity:   "High",
// 					FixedState: string(v5.FixedState),
// 				},
// 				{
// 					ID:         "CVE-2020-1235",
// 					Severity:   "High",
// 					FixedState: string(v5.NotFixedState),
// 				},
// 				{
// 					ID:         "CVE-2020-23",
// 					Severity:   "Low",
// 					FixedState: string(v5.NotFixedState),
// 				},
// 				{
// 					ID:         "CVE-2020-4321",
// 					Severity:   "Medium",
// 					FixedState: string(v5.NotFixedState),
// 				},
// 				{
// 					ID:         "CVE-2020-53152",
// 					Severity:   "Negligible",
// 					FixedState: string(v5.NotFixedState),
// 				},
// 				{
// 					ID:         "CVE-2020-531524",
// 					Severity:   "Negligible",
// 					FixedState: string(v5.NotFixedState),
// 				},
// 			},
// 			want: map[string]*imageprinter.SeveritySummary{
// 				"High": {
// 					NumberOfCVEs:        2,
// 					NumberOfFixableCVEs: 1,
// 				},
// 				"Low": {
// 					NumberOfCVEs:        1,
// 					NumberOfFixableCVEs: 0,
// 				},
// 				"Medium": {
// 					NumberOfCVEs:        1,
// 					NumberOfFixableCVEs: 0,
// 				},
// 				"Negligible": {
// 					NumberOfCVEs:        2,
// 					NumberOfFixableCVEs: 0,
// 				},
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			actual := extractSeverityToSummaryMap(tt.cves)
// 			if len(actual) == 0 {
// 				assert.Equal(t, tt.want, actual)
// 				return
// 			}

// 			if len(actual) != len(tt.want) {
// 				t.Errorf("extractSeverityToSummaryMap() = %v, want %v", actual, tt.want)
// 			}

// 			for k := range actual {
// 				if actual[k].NumberOfCVEs != tt.want[k].NumberOfCVEs {
// 					t.Errorf("extractSeverityToSummaryMap() = %v, want %v", actual, tt.want)
// 				}
// 				if actual[k].NumberOfFixableCVEs != tt.want[k].NumberOfFixableCVEs {
// 					t.Errorf("extractSeverityToSummaryMap() = %v, want %v", actual, tt.want)
// 				}
// 			}
// 		})
// 	}
// }
