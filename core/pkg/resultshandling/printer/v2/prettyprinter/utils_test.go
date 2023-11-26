package prettyprinter

import (
	"reflect"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
)

func TestFilterComplianceFrameworks(t *testing.T) {
	tests := []struct {
		name                   string
		summaryDetails         *reportsummary.SummaryDetails
		expectedSummaryDetails *reportsummary.SummaryDetails
	}{
		{
			name: "check compliance frameworks are filtered",
			summaryDetails: &reportsummary.SummaryDetails{
				Frameworks: []reportsummary.FrameworkSummary{
					{
						Name: "CIS Kubernetes Benchmark",
					},
					{
						Name: "nsa",
					},
					{
						Name: "mitre",
					},
				},
			},
			expectedSummaryDetails: &reportsummary.SummaryDetails{
				Frameworks: []reportsummary.FrameworkSummary{
					{
						Name: "nsa",
					},
					{
						Name: "mitre",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			complianceFws := filterComplianceFrameworks(tt.summaryDetails.ListFrameworks())
			assert.True(t, reflect.DeepEqual(complianceFws, tt.expectedSummaryDetails.ListFrameworks()))
		})
	}
}

func TestGetWorkloadPrefixForCmd(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		kind      string
		name1     string
		want      string
	}{
		{
			name:      "non-empty namespace",
			namespace: "default",
			kind:      "pod",
			name1:     "test",
			want:      "namespace: default, name: test, kind: pod",
		},
		{
			name:      "empty namespace",
			namespace: "",
			kind:      "pod",
			name1:     "test",
			want:      "name: test, kind: pod",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getWorkloadPrefixForCmd(tt.namespace, tt.kind, tt.name1); got != tt.want {
				t.Errorf("getWorkloadPrefixForCmd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTopWorkloadsTitle(t *testing.T) {
	title := getTopWorkloadsTitle(0)
	assert.Equal(t, "", title)

	title = getTopWorkloadsTitle(1)
	assert.Equal(t, "Highest-stake workloads", title)

	title = getTopWorkloadsTitle(2)
	assert.Equal(t, "Highest-stake workloads", title)

	title = getTopWorkloadsTitle(10)
	assert.Equal(t, "Highest-stake workloads", title)
}

func TestGetSeverityToSummaryMap(t *testing.T) {
	tests := []struct {
		name           string
		summaryDetails imageprinter.ImageScanSummary
		expected       map[string]imageprinter.SeveritySummary
		verboseMode    bool
	}{
		{
			name: "without merging",
			summaryDetails: imageprinter.ImageScanSummary{
				MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{
					"High": {
						NumberOfCVEs:        10,
						NumberOfFixableCVEs: 2,
					},
					"Low": {
						NumberOfCVEs:        5,
						NumberOfFixableCVEs: 1,
					},
					"Negligible": {
						NumberOfCVEs:        3,
						NumberOfFixableCVEs: 0,
					},
				},
			},
			verboseMode: true,
			expected: map[string]imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        10,
					NumberOfFixableCVEs: 2,
				},
				"Low": {
					NumberOfCVEs:        5,
					NumberOfFixableCVEs: 1,
				},
				"Negligible": {
					NumberOfCVEs:        3,
					NumberOfFixableCVEs: 0,
				},
			},
		},
		{
			name: "with merging",
			summaryDetails: imageprinter.ImageScanSummary{
				MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{
					"Critical": {
						NumberOfCVEs:        15,
						NumberOfFixableCVEs: 2,
					},
					"High": {
						NumberOfCVEs:        10,
						NumberOfFixableCVEs: 2,
					},
					"Medium": {
						NumberOfCVEs:        5,
						NumberOfFixableCVEs: 1,
					},
					"Low": {
						NumberOfCVEs:        5,
						NumberOfFixableCVEs: 1,
					},
					"Negligible": {
						NumberOfCVEs:        3,
						NumberOfFixableCVEs: 0,
					},
				},
			},
			verboseMode: false,
			expected: map[string]imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        15,
					NumberOfFixableCVEs: 2,
				},
				"High": {
					NumberOfCVEs:        10,
					NumberOfFixableCVEs: 2,
				},
				"Medium": {
					NumberOfCVEs:        5,
					NumberOfFixableCVEs: 1,
				},
				"Other": {
					NumberOfCVEs:        8,
					NumberOfFixableCVEs: 1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sevToSummaryMap := getSeverityToSummaryMap(tt.summaryDetails, tt.verboseMode)

			for k, v := range sevToSummaryMap {
				if v.NumberOfCVEs != tt.expected[k].NumberOfCVEs || v.NumberOfFixableCVEs != tt.expected[k].NumberOfFixableCVEs {
					t.Errorf("in test: %v, error for key %v, want: %v, have :%v", tt.name, k, tt.expected[k], v)
				}
			}
		})
	}
}

func TestFilterCVEsBySeverities(t *testing.T) {
	test := []struct {
		name         string
		cves         []imageprinter.CVE
		severities   []string
		expectedCVEs []imageprinter.CVE
	}{
		{
			name: "empty severities list",
			cves: []imageprinter.CVE{
				{
					Severity: "High",
					ID:       "CVE-2020-1234",
				},
			},
			severities:   []string{},
			expectedCVEs: []imageprinter.CVE{},
		},
		{
			name: "one severity",
			cves: []imageprinter.CVE{
				{
					Severity: "High",
					ID:       "CVE-2020-1234",
				},
				{
					Severity: "Medium",
					ID:       "CVE-2020-1235",
				},
			},
			severities: []string{"High"},
			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "High",
					ID:       "CVE-2020-1234",
				},
			},
		},
		{
			name: "multiple severities",
			cves: []imageprinter.CVE{
				{
					Severity: "High",
					ID:       "CVE-2020-1234",
				},
				{
					Severity: "Medium",
					ID:       "CVE-2020-1235",
				},
				{
					Severity: "Low",
					ID:       "CVE-2020-1236",
				},
			},
			severities: []string{"High", "Low"},
			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "High",
					ID:       "CVE-2020-1234",
				},
				{
					Severity: "Low",
					ID:       "CVE-2020-1236",
				},
			},
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			filteredCVEs := filterCVEsBySeverities(tt.cves, tt.severities)

			for i := range filteredCVEs {
				if filteredCVEs[i].Severity != tt.expectedCVEs[i].Severity || filteredCVEs[i].ID != tt.expectedCVEs[i].ID {
					t.Errorf("filterCVEsBySeverities() = %v, want %v", filteredCVEs, tt.expectedCVEs)
				}
			}

		})
	}

}

func TestGetSortPackageScores(t *testing.T) {
	tests := []struct {
		name           string
		pkgScores      map[string]*imageprinter.PackageScore
		expectedResult []string
	}{
		{
			name: "Non-empty input",
			pkgScores: map[string]*imageprinter.PackageScore{
				"packageA": {
					Name:                    "packageA",
					Version:                 "1.0",
					Score:                   10,
					MapSeverityToCVEsNumber: map[string]int{},
				},
				"packageB": {
					Name:                    "packageB",
					Version:                 "2.0",
					Score:                   5,
					MapSeverityToCVEsNumber: map[string]int{},
				},
				"packageC": {
					Name:                    "packageC",
					Version:                 "3.0",
					Score:                   8,
					MapSeverityToCVEsNumber: map[string]int{},
				},
			},
			expectedResult: []string{"packageA", "packageC", "packageB"},
		},
		{
			name:           "Empty input",
			pkgScores:      map[string]*imageprinter.PackageScore{},
			expectedResult: []string{},
		},
		{
			name: "Non-empty input, same score",
			pkgScores: map[string]*imageprinter.PackageScore{
				"packageA": {
					Name:                    "packageA",
					Version:                 "1.0",
					Score:                   10,
					MapSeverityToCVEsNumber: map[string]int{},
				},
				"packageB": {
					Name:                    "packageB",
					Version:                 "2.0",
					Score:                   10,
					MapSeverityToCVEsNumber: map[string]int{},
				},
			},
			expectedResult: []string{"packageA", "packageB"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sortedNames := getSortPackageScores(tc.pkgScores)

			for i := range sortedNames {
				if sortedNames[i] != tc.expectedResult[i] {
					t.Errorf("Expected: %v, Got: %v", tc.expectedResult, sortedNames)
				}
			}
		})
	}
}

func TestAddEmptySeverities(t *testing.T) {
	tests := []struct {
		name           string
		summaryDetails map[string]*imageprinter.SeveritySummary
		expectedResult map[string]*imageprinter.SeveritySummary
		verboseMode    bool
	}{
		{
			name:        "Non-empty input",
			verboseMode: true,
			summaryDetails: map[string]*imageprinter.SeveritySummary{
				"High": {
					NumberOfCVEs:        10,
					NumberOfFixableCVEs: 2,
				},
				"Low": {
					NumberOfCVEs:        5,
					NumberOfFixableCVEs: 1,
				},
			},
			expectedResult: map[string]*imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"High": {
					NumberOfCVEs:        10,
					NumberOfFixableCVEs: 2,
				},
				"Medium": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Low": {
					NumberOfCVEs:        5,
					NumberOfFixableCVEs: 1,
				},
				"Negligible": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Unknown": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
			},
		},
		{
			name:           "Empty input",
			verboseMode:    true,
			summaryDetails: map[string]*imageprinter.SeveritySummary{},
			expectedResult: map[string]*imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"High": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Medium": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Low": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Negligible": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Unknown": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
			},
		},
		{
			name:        "Non-empty input, non-verbose mode",
			verboseMode: false,
			summaryDetails: map[string]*imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 2,
				},
			},
			expectedResult: map[string]*imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        1,
					NumberOfFixableCVEs: 2,
				},
				"High": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Medium": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Other": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
			},
		},
		{
			name:           "Empty input, non-verbose mode",
			verboseMode:    false,
			summaryDetails: map[string]*imageprinter.SeveritySummary{},
			expectedResult: map[string]*imageprinter.SeveritySummary{
				"Critical": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"High": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Medium": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
				"Other": {
					NumberOfCVEs:        0,
					NumberOfFixableCVEs: 0,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addEmptySeverities(tc.summaryDetails, tc.verboseMode)

			for k, v := range tc.summaryDetails {
				if v.NumberOfCVEs != tc.expectedResult[k].NumberOfCVEs || v.NumberOfFixableCVEs != tc.expectedResult[k].NumberOfFixableCVEs {
					t.Errorf("in test: %v, error for key %v, want: %v, have :%v", tc.name, k, tc.expectedResult[k], v)
				}
			}
		})
	}
}

func TestGetSortedCVEsBySeverity(t *testing.T) {
	tests := []struct {
		name           string
		severityToCVEs map[string]int
		expectedResult []string
	}{
		{
			name: "Unsorted input",
			severityToCVEs: map[string]int{
				"Critical": 2,
				"Medium":   2,
				"High":     2,
				"Unknown":  2,
				"Low":      2,
			},
			expectedResult: []string{"Critical", "High", "Medium", "Low", "Unknown"},
		},
		{
			name: "Sorted input",
			severityToCVEs: map[string]int{
				"Critical": 1,
				"High":     2,
				"Medium":   3,
				"Low":      4,
			},
			expectedResult: []string{"Critical", "High", "Medium", "Low"},
		},
		{
			name:           "Empty input",
			severityToCVEs: map[string]int{},
			expectedResult: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sortedCVEs := getSortedCVEsBySeverity(tc.severityToCVEs)

			for i := range sortedCVEs {
				if sortedCVEs[i] != tc.expectedResult[i] {
					t.Errorf("Expected: %v, Got: %v", tc.expectedResult, sortedCVEs)
				}
			}
		})
	}
}

func TestGetFilteredCVEs(t *testing.T) {
	tests := []struct {
		name         string
		cves         []imageprinter.CVE
		expectedCVEs []imageprinter.CVE
	}{
		{
			name: "High and Critical",
			cves: []imageprinter.CVE{
				{
					Severity: "High",
				},
				{
					Severity: "Critical",
				},
				{
					Severity: "Medium",
				},
				{
					Severity: "Low",
				},
				{
					Severity: "Negligible",
				},
			},
			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "High",
				},
				{
					Severity: "Critical",
				},
			},
		},
		{
			name: "Only High",
			cves: []imageprinter.CVE{
				{
					Severity: "High",
				},
				{
					Severity: "Medium",
				}},
			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "High",
				},
			},
		},
		{
			name: "Only Critical",
			cves: []imageprinter.CVE{
				{
					Severity: "Critical",
				},
				{
					Severity: "Medium",
				}},
			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "Critical",
				},
			},
		},
		{
			name: "No High or Critical",
			cves: []imageprinter.CVE{
				{
					Severity: "Low",
				},
				{
					Severity: "Medium",
				}},

			expectedCVEs: []imageprinter.CVE{
				{
					Severity: "Medium",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filteredCVEs := getFilteredCVEs(tc.cves)
			for _, cve := range filteredCVEs {
				found := false
				for _, expectedCVE := range tc.expectedCVEs {
					if cve.Severity == expectedCVE.Severity {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected: %v, Got: %v", tc.expectedCVEs, filteredCVEs)
				}
			}
		})
	}
}
