package prettyprinter

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestPrintImagesCommandsUsesFullImageReference(t *testing.T) {
	tests := []struct {
		name        string
		images      []string
		wantGeneric bool
	}{
		{
			name:   "tagged short names remain distinct",
			images: []string{"nginx:1.25", "nginx:1.27"},
		},
		{
			name:   "registry port is preserved",
			images: []string{"localhost:5000/team/api:v1"},
		},
		{
			name: "digest is preserved",
			images: []string{
				"registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name:        "large image sets keep the generic hint",
			images:      []string{"one:v1", "two:v2", "three:v3", "four:v4"},
			wantGeneric: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := capturePrintImagesCommands(t, tt.images)
			if tt.wantGeneric {
				assert.Contains(t, output, "Receive a full report by running: kubescape scan image <image>")
				for _, image := range tt.images {
					assert.NotContains(t, output, image)
				}
				return
			}

			for _, image := range tt.images {
				assert.Equal(t, 1, strings.Count(output, image),
					"the command should contain the full image reference exactly once")
			}
			assert.NotContains(t, output, "Receive a full report for ")
		})
	}
}

func capturePrintImagesCommands(t *testing.T, images []string) string {
	t.Helper()

	output, err := os.CreateTemp(t.TempDir(), "image-commands-*.txt")
	require.NoError(t, err)
	defer output.Close()

	printImagesCommands(output, imageprinter.ImageScanSummary{Images: images})
	require.NoError(t, output.Sync())
	_, err = output.Seek(0, io.SeekStart)
	require.NoError(t, err)
	contents, err := io.ReadAll(output)
	require.NoError(t, err)
	return string(contents)
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

// TestPrintTopComponents_PackageNameWithPercentVerbs guards against a
// regression where a pre-built package summary line was passed as the format
// argument to cautils.StarDisplay instead of as a %s value: a package name
// containing %-verbs (reachable from scanned image metadata) was silently
// corrupted by fmt's format-string interpretation instead of being printed
// literally.
func TestPrintTopComponents_PackageNameWithPercentVerbs(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-components")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	name := "left-pad-%s-%d-leaked"
	summary := imageprinter.ImageScanSummary{
		PackageScores: map[string]*imageprinter.PackageScore{
			name: {
				Name:    name,
				Version: "1.0.0",
			},
		},
	}

	printTopComponents(f, summary)

	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	assert.Contains(t, string(got), name, "package name must be printed literally, not interpreted as a format string")
}
