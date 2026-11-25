package printer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComplianceScore_MetricsLabelsAndPrefix(t *testing.T) {
	tests := []struct {
		name            string
		mrs             mComplianceScore
		expectedMetrics []string
	}{
		{
			name: "All metrics equal",
			mrs: mComplianceScore{
				resourcesCountPassed:  7,
				resourcesCountSkipped: 7,
				resourcesCountFailed:  7,
				controlsCountPassed:   7,
				controlsCountSkipped:  7,
				controlsCountFailed:   7,
				complianceScore:       7,
			},
			expectedMetrics: []string{"kubescape_cluster_complianceScore{} 7", "kubescape_cluster_count_resources_failed{} 7", "kubescape_cluster_count_resources_skipped{} 7", "kubescape_cluster_count_resources_passed{} 7", "kubescape_cluster_count_control_failed{} 7", "kubescape_cluster_count_control_skipped{} 7", "kubescape_cluster_count_control_passed{} 7"},
		},
		{
			name:            "All metrics empty",
			mrs:             mComplianceScore{},
			expectedMetrics: []string{"kubescape_cluster_complianceScore{} 0", "kubescape_cluster_count_resources_failed{} 0", "kubescape_cluster_count_resources_skipped{} 0", "kubescape_cluster_count_resources_passed{} 0", "kubescape_cluster_count_control_failed{} 0", "kubescape_cluster_count_control_skipped{} 0", "kubescape_cluster_count_control_passed{} 0"},
		},
		{
			name: "All metrics unequal",
			mrs: mComplianceScore{
				resourcesCountPassed:  7,
				resourcesCountSkipped: 17,
				resourcesCountFailed:  27,
				controlsCountPassed:   37,
				controlsCountSkipped:  47,
				controlsCountFailed:   57,
				complianceScore:       67,
			},
			expectedMetrics: []string{"kubescape_cluster_complianceScore{} 67", "kubescape_cluster_count_resources_failed{} 27", "kubescape_cluster_count_resources_skipped{} 17", "kubescape_cluster_count_resources_passed{} 7", "kubescape_cluster_count_control_failed{} 57", "kubescape_cluster_count_control_skipped{} 47", "kubescape_cluster_count_control_passed{} 37"},
		},
		{
			name: "Unset compliance score omits only the score metric",
			mrs: mComplianceScore{
				resourcesCountPassed:  7,
				resourcesCountSkipped: 17,
				resourcesCountFailed:  27,
				controlsCountPassed:   37,
				controlsCountSkipped:  47,
				controlsCountFailed:   57,
				complianceScore:       -1,
			},
			expectedMetrics: []string{
				"kubescape_cluster_count_resources_failed{} 27",
				"kubescape_cluster_count_resources_skipped{} 17",
				"kubescape_cluster_count_resources_passed{} 7",
				"kubescape_cluster_count_control_failed{} 57",
				"kubescape_cluster_count_control_skipped{} 47",
				"kubescape_cluster_count_control_passed{} 37",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := tt.mrs.metrics()
			assert.Equal(t, tt.expectedMetrics, actualMetrics)
			assert.Equal(t, "", tt.mrs.labels())
			assert.Equal(t, "kubescape_cluster", tt.mrs.prefix())
		})
	}
}

func TestMetricsString_EscapesDynamicLabelValues(t *testing.T) {
	value := "quote\" slash\\ newline\nnext"
	parse := func(t *testing.T, exposition string) func(string) map[string]string {
		t.Helper()
		parser := expfmt.NewTextParser(model.LegacyValidation)
		families, err := parser.TextToMetricFamilies(strings.NewReader(exposition))
		require.NoErrorf(t, err, "invalid Prometheus exposition:\n%s", exposition)

		return func(familyName string) map[string]string {
			t.Helper()
			family, ok := families[familyName]
			require.Truef(t, ok, "metric family %q is missing", familyName)
			require.Len(t, family.Metric, 1)
			labels := map[string]string{}
			for _, label := range family.Metric[0].Label {
				labels[label.GetName()] = label.GetValue()
			}
			return labels
		}
	}

	t.Run("posture scan", func(t *testing.T) {
		// Custom policies loaded with --use-from can define framework and
		// control names containing any JSON string. Drive the same
		// SummaryDetails -> Metrics path as the Prometheus printer.
		controlScore := float32(50)
		summary := &reportsummary.SummaryDetails{
			Frameworks: []reportsummary.FrameworkSummary{{Name: value, ComplianceScore: 50}},
			Controls: reportsummary.ControlSummaries{
				"C-ESCAPE": {
					ControlID:       "C-ESCAPE",
					Name:            value,
					ComplianceScore: &controlScore,
				},
			},
		}
		metricsOutput := &Metrics{}
		metricsOutput.setComplianceScores(summary)
		metricsOutput.listResources = []mResources{{
			apiVersion: value,
			kind:       value,
			namespace:  value,
			name:       value,
		}}

		labelsFor := parse(t, metricsOutput.String())
		assert.Equal(t, value, labelsFor("kubescape_framework_complianceScore")["name"])
		assert.Equal(t, value, labelsFor("kubescape_control_complianceScore")["name"])
		assert.Equal(t, map[string]string{
			"apiVersion": value,
			"kind":       value,
			"namespace":  value,
			"name":       value,
		}, labelsFor("kubescape_resource_count_controls_failed"))
	})

	t.Run("image scan", func(t *testing.T) {
		metricsOutput := &Metrics{
			isImageScan: true,
			listImages: []mImageVulnerability{{
				image:    value,
				severity: value,
				cveCount: 1,
			}},
		}

		labelsFor := parse(t, metricsOutput.String())
		assert.Equal(t, map[string]string{
			"image":    value,
			"severity": value,
		}, labelsFor("kubescape_image_count_cve"))
	})
}

func TestControlComplianceScore_MetricsLabelsAndPrefix(t *testing.T) {
	tests := []struct {
		name            string
		mcrs            mControlComplianceScore
		expectedMetrics []string
		expectedLabels  string
	}{
		{
			name:            "All metrics empty",
			mcrs:            mControlComplianceScore{},
			expectedMetrics: []string{"kubescape_control_complianceScore{name=\"\",severity=\"\",link=\"\"} 0", "kubescape_control_count_resources_failed{name=\"\",severity=\"\",link=\"\"} 0", "kubescape_control_count_resources_skipped{name=\"\",severity=\"\",link=\"\"} 0", "kubescape_control_count_resources_passed{name=\"\",severity=\"\",link=\"\"} 0"},
			expectedLabels:  "name=\"\",severity=\"\",link=\"\"",
		},
		{
			name: "All metrics equal",
			mcrs: mControlComplianceScore{
				controlName:           "Test Control",
				controlID:             "Test ID",
				link:                  "https://test-link.com",
				severity:              "high",
				remediation:           "not-known",
				resourcesCountPassed:  7,
				resourcesCountFailed:  7,
				resourcesCountSkipped: 7,
				complianceScore:       7,
			},
			expectedMetrics: []string{"kubescape_control_complianceScore{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7", "kubescape_control_count_resources_failed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7", "kubescape_control_count_resources_skipped{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7", "kubescape_control_count_resources_passed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7"},
			expectedLabels:  "name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"",
		},
		{
			name: "All metrics different",
			mcrs: mControlComplianceScore{
				controlName:           "Test Control",
				controlID:             "Test ID",
				link:                  "https://test-link.com",
				severity:              "high",
				remediation:           "not-known",
				resourcesCountPassed:  7,
				resourcesCountFailed:  17,
				resourcesCountSkipped: 27,
				complianceScore:       37,
			},
			expectedMetrics: []string{"kubescape_control_complianceScore{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 37", "kubescape_control_count_resources_failed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 17", "kubescape_control_count_resources_skipped{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 27", "kubescape_control_count_resources_passed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7"},
			expectedLabels:  "name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"",
		},
		{
			name: "Unset compliance score omits only the score metric",
			mcrs: mControlComplianceScore{
				controlName:           "Unset Control",
				resourcesCountPassed:  7,
				resourcesCountFailed:  17,
				resourcesCountSkipped: 27,
				complianceScore:       -1,
			},
			expectedMetrics: []string{"kubescape_control_count_resources_failed{name=\"Unset Control\",severity=\"\",link=\"\"} 17", "kubescape_control_count_resources_skipped{name=\"Unset Control\",severity=\"\",link=\"\"} 27", "kubescape_control_count_resources_passed{name=\"Unset Control\",severity=\"\",link=\"\"} 7"},
			expectedLabels:  "name=\"Unset Control\",severity=\"\",link=\"\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := tt.mcrs.metrics()
			assert.Equal(t, tt.expectedMetrics, actualMetrics)
			assert.Equal(t, tt.expectedLabels, tt.mcrs.labels())
			assert.Equal(t, "kubescape_control", tt.mcrs.prefix())
		})
	}
}

func TestFrameworkComplianceScore_MetricsLabelsAndPrefix(t *testing.T) {
	tests := []struct {
		name            string
		mfrs            mFrameworkComplianceScore
		expectedMetrics []string
		expectedLabels  string
	}{
		{
			name:            "All metrics empty",
			mfrs:            mFrameworkComplianceScore{},
			expectedMetrics: []string{"kubescape_framework_complianceScore{name=\"\"} 0", "kubescape_framework_count_resources_failed{name=\"\"} 0", "kubescape_framework_count_resources_skipped{name=\"\"} 0", "kubescape_framework_count_resources_passed{name=\"\"} 0", "kubescape_framework_count_control_failed{name=\"\"} 0", "kubescape_framework_count_control_skipped{name=\"\"} 0", "kubescape_framework_count_control_passed{name=\"\"} 0"},
			expectedLabels:  "name=\"\"",
		},
		{
			name: "All metrics equal",
			mfrs: mFrameworkComplianceScore{
				frameworkName:         "Test Framework 2",
				controlsCountPassed:   7,
				controlsCountFailed:   7,
				controlsCountSkipped:  7,
				resourcesCountPassed:  7,
				resourcesCountFailed:  7,
				resourcesCountSkipped: 7,
				complianceScore:       7,
			},
			expectedMetrics: []string{"kubescape_framework_complianceScore{name=\"Test Framework 2\"} 7", "kubescape_framework_count_resources_failed{name=\"Test Framework 2\"} 7", "kubescape_framework_count_resources_skipped{name=\"Test Framework 2\"} 7", "kubescape_framework_count_resources_passed{name=\"Test Framework 2\"} 7", "kubescape_framework_count_control_failed{name=\"Test Framework 2\"} 7", "kubescape_framework_count_control_skipped{name=\"Test Framework 2\"} 7", "kubescape_framework_count_control_passed{name=\"Test Framework 2\"} 7"},
			expectedLabels:  "name=\"Test Framework 2\"",
		},
		{
			name: "All metrics different",
			mfrs: mFrameworkComplianceScore{
				frameworkName:         "Test Framework 3",
				controlsCountPassed:   7,
				controlsCountFailed:   17,
				controlsCountSkipped:  27,
				resourcesCountPassed:  37,
				resourcesCountFailed:  47,
				resourcesCountSkipped: 57,
				complianceScore:       67,
			},
			expectedMetrics: []string{"kubescape_framework_complianceScore{name=\"Test Framework 3\"} 67", "kubescape_framework_count_resources_failed{name=\"Test Framework 3\"} 47", "kubescape_framework_count_resources_skipped{name=\"Test Framework 3\"} 57", "kubescape_framework_count_resources_passed{name=\"Test Framework 3\"} 37", "kubescape_framework_count_control_failed{name=\"Test Framework 3\"} 17", "kubescape_framework_count_control_skipped{name=\"Test Framework 3\"} 27", "kubescape_framework_count_control_passed{name=\"Test Framework 3\"} 7"},
			expectedLabels:  "name=\"Test Framework 3\"",
		},
		{
			name: "Unset compliance score omits only the score metric",
			mfrs: mFrameworkComplianceScore{
				frameworkName:         "Unset Framework",
				controlsCountPassed:   7,
				controlsCountFailed:   17,
				controlsCountSkipped:  27,
				resourcesCountPassed:  37,
				resourcesCountFailed:  47,
				resourcesCountSkipped: 57,
				complianceScore:       -1,
			},
			expectedMetrics: []string{
				"kubescape_framework_count_resources_failed{name=\"Unset Framework\"} 47",
				"kubescape_framework_count_resources_skipped{name=\"Unset Framework\"} 57",
				"kubescape_framework_count_resources_passed{name=\"Unset Framework\"} 37",
				"kubescape_framework_count_control_failed{name=\"Unset Framework\"} 17",
				"kubescape_framework_count_control_skipped{name=\"Unset Framework\"} 27",
				"kubescape_framework_count_control_passed{name=\"Unset Framework\"} 7",
			},
			expectedLabels: "name=\"Unset Framework\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := tt.mfrs.metrics()
			assert.Equal(t, tt.expectedMetrics, actualMetrics)
			assert.Equal(t, tt.expectedLabels, tt.mfrs.labels())
			assert.Equal(t, "kubescape_framework", tt.mfrs.prefix())
		})
	}
}

func TestResources_MetricsLabelsAndPrefix(t *testing.T) {
	tests := []struct {
		name            string
		mrc             mResources
		expectedMetrics []string
		expectedLabels  string
	}{
		{
			name:            "Empty Resource",
			mrc:             mResources{},
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"} 0", "kubescape_resource_count_controls_skipped{apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"} 0", "kubescape_resource_count_controls_passed{apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"} 0"},
			expectedLabels:  "apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"",
		},
		{
			name: "Non empty Resource",
			mrc: mResources{
				name:                 "Test Resource",
				namespace:            "Test",
				apiVersion:           "v1",
				kind:                 "Test",
				controlsCountPassed:  7,
				controlsCountFailed:  7,
				controlsCountSkipped: 7,
			},
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"} 7", "kubescape_resource_count_controls_skipped{apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"} 7", "kubescape_resource_count_controls_passed{apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"} 7"},
			expectedLabels:  "apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"",
		},
		{
			name: "Non empty Resource 2",
			mrc: mResources{
				name:                 "Test Resource 2",
				namespace:            "Test",
				apiVersion:           "v2",
				kind:                 "Test",
				controlsCountPassed:  27,
				controlsCountFailed:  7,
				controlsCountSkipped: 17,
			},
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 7", "kubescape_resource_count_controls_skipped{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 17", "kubescape_resource_count_controls_passed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 27"},
			expectedLabels:  "apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := tt.mrc.metrics()
			assert.Equal(t, tt.expectedMetrics, actualMetrics)
			assert.Equal(t, tt.expectedLabels, tt.mrc.labels())
			assert.Equal(t, "kubescape_resource", tt.mrc.prefix())
		})
	}
}

func TestToRowInMetrics(t *testing.T) {
	tests := []struct {
		name     string
		row      string
		value    int
		expected string
	}{
		{
			name:     "name",
			row:      "row",
			value:    77,
			expected: "name{row} 77",
		},
		{
			name:     "name",
			row:      "row",
			value:    0,
			expected: "name{row} 0",
		},
		{
			name:     "name",
			row:      "",
			value:    10,
			expected: "name{} 10",
		},
		{
			name:     "",
			row:      "row",
			value:    10,
			expected: "{row} 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := toRowInMetrics(tt.name, tt.row, tt.value)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestMetrics_String(t *testing.T) {
	tests := []struct {
		name            string
		m               Metrics
		expectedMetrics string
	}{
		{
			name:            "Empty Metrics",
			m:               Metrics{},
			expectedMetrics: "# HELP kubescape_cluster_complianceScore kubescape_cluster_complianceScore\n# TYPE kubescape_cluster_complianceScore gauge\nkubescape_cluster_complianceScore{} 0\n# HELP kubescape_cluster_count_resources_failed kubescape_cluster_count_resources_failed\n# TYPE kubescape_cluster_count_resources_failed gauge\nkubescape_cluster_count_resources_failed{} 0\n# HELP kubescape_cluster_count_resources_skipped kubescape_cluster_count_resources_skipped\n# TYPE kubescape_cluster_count_resources_skipped gauge\nkubescape_cluster_count_resources_skipped{} 0\n# HELP kubescape_cluster_count_resources_passed kubescape_cluster_count_resources_passed\n# TYPE kubescape_cluster_count_resources_passed gauge\nkubescape_cluster_count_resources_passed{} 0\n# HELP kubescape_cluster_count_control_failed kubescape_cluster_count_control_failed\n# TYPE kubescape_cluster_count_control_failed gauge\nkubescape_cluster_count_control_failed{} 0\n# HELP kubescape_cluster_count_control_skipped kubescape_cluster_count_control_skipped\n# TYPE kubescape_cluster_count_control_skipped gauge\nkubescape_cluster_count_control_skipped{} 0\n# HELP kubescape_cluster_count_control_passed kubescape_cluster_count_control_passed\n# TYPE kubescape_cluster_count_control_passed gauge\nkubescape_cluster_count_control_passed{} 0\n# HELP kubescape_cluster_coverage_score kubescape_cluster_coverage_score\n# TYPE kubescape_cluster_coverage_score gauge\nkubescape_cluster_coverage_score{} 0\n",
		},
		{
			name: "Empty Metrics",
			m: Metrics{
				listFrameworks: []mFrameworkComplianceScore{
					{
						frameworkName:         "Test Framework 3",
						controlsCountPassed:   7,
						controlsCountFailed:   17,
						controlsCountSkipped:  27,
						resourcesCountPassed:  37,
						resourcesCountFailed:  47,
						resourcesCountSkipped: 57,
						complianceScore:       67,
					},
				},
				listControls: []mControlComplianceScore{
					{
						controlName:           "Test Control",
						controlID:             "Test ID",
						link:                  "https://test-link.com",
						severity:              "high",
						remediation:           "not-known",
						resourcesCountPassed:  7,
						resourcesCountFailed:  7,
						resourcesCountSkipped: 7,
						complianceScore:       7,
					},
				},
				listResources: []mResources{
					{
						name:                 "Test Resource 2",
						namespace:            "Test",
						apiVersion:           "v2",
						kind:                 "Test",
						controlsCountFailed:  7,
						controlsCountSkipped: 17,
					},
				},
			},
			expectedMetrics: "# HELP kubescape_cluster_complianceScore kubescape_cluster_complianceScore\n# TYPE kubescape_cluster_complianceScore gauge\nkubescape_cluster_complianceScore{} 0\n# HELP kubescape_cluster_count_resources_failed kubescape_cluster_count_resources_failed\n# TYPE kubescape_cluster_count_resources_failed gauge\nkubescape_cluster_count_resources_failed{} 0\n# HELP kubescape_cluster_count_resources_skipped kubescape_cluster_count_resources_skipped\n# TYPE kubescape_cluster_count_resources_skipped gauge\nkubescape_cluster_count_resources_skipped{} 0\n# HELP kubescape_cluster_count_resources_passed kubescape_cluster_count_resources_passed\n# TYPE kubescape_cluster_count_resources_passed gauge\nkubescape_cluster_count_resources_passed{} 0\n# HELP kubescape_cluster_count_control_failed kubescape_cluster_count_control_failed\n# TYPE kubescape_cluster_count_control_failed gauge\nkubescape_cluster_count_control_failed{} 0\n# HELP kubescape_cluster_count_control_skipped kubescape_cluster_count_control_skipped\n# TYPE kubescape_cluster_count_control_skipped gauge\nkubescape_cluster_count_control_skipped{} 0\n# HELP kubescape_cluster_count_control_passed kubescape_cluster_count_control_passed\n# TYPE kubescape_cluster_count_control_passed gauge\nkubescape_cluster_count_control_passed{} 0\n# HELP kubescape_cluster_coverage_score kubescape_cluster_coverage_score\n# TYPE kubescape_cluster_coverage_score gauge\nkubescape_cluster_coverage_score{} 0\n# HELP kubescape_framework_complianceScore kubescape_framework_complianceScore\n# TYPE kubescape_framework_complianceScore gauge\nkubescape_framework_complianceScore{name=\"Test Framework 3\"} 67\n# HELP kubescape_framework_count_resources_failed kubescape_framework_count_resources_failed\n# TYPE kubescape_framework_count_resources_failed gauge\nkubescape_framework_count_resources_failed{name=\"Test Framework 3\"} 47\n# HELP kubescape_framework_count_resources_skipped kubescape_framework_count_resources_skipped\n# TYPE kubescape_framework_count_resources_skipped gauge\nkubescape_framework_count_resources_skipped{name=\"Test Framework 3\"} 57\n# HELP kubescape_framework_count_resources_passed kubescape_framework_count_resources_passed\n# TYPE kubescape_framework_count_resources_passed gauge\nkubescape_framework_count_resources_passed{name=\"Test Framework 3\"} 37\n# HELP kubescape_framework_count_control_failed kubescape_framework_count_control_failed\n# TYPE kubescape_framework_count_control_failed gauge\nkubescape_framework_count_control_failed{name=\"Test Framework 3\"} 17\n# HELP kubescape_framework_count_control_skipped kubescape_framework_count_control_skipped\n# TYPE kubescape_framework_count_control_skipped gauge\nkubescape_framework_count_control_skipped{name=\"Test Framework 3\"} 27\n# HELP kubescape_framework_count_control_passed kubescape_framework_count_control_passed\n# TYPE kubescape_framework_count_control_passed gauge\nkubescape_framework_count_control_passed{name=\"Test Framework 3\"} 7\n# HELP kubescape_control_complianceScore kubescape_control_complianceScore\n# TYPE kubescape_control_complianceScore gauge\nkubescape_control_complianceScore{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\n# HELP kubescape_control_count_resources_failed kubescape_control_count_resources_failed\n# TYPE kubescape_control_count_resources_failed gauge\nkubescape_control_count_resources_failed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\n# HELP kubescape_control_count_resources_skipped kubescape_control_count_resources_skipped\n# TYPE kubescape_control_count_resources_skipped gauge\nkubescape_control_count_resources_skipped{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\n# HELP kubescape_control_count_resources_passed kubescape_control_count_resources_passed\n# TYPE kubescape_control_count_resources_passed gauge\nkubescape_control_count_resources_passed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\n# HELP kubescape_resource_count_controls_failed kubescape_resource_count_controls_failed\n# TYPE kubescape_resource_count_controls_failed gauge\nkubescape_resource_count_controls_failed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 7\n# HELP kubescape_resource_count_controls_skipped kubescape_resource_count_controls_skipped\n# TYPE kubescape_resource_count_controls_skipped gauge\nkubescape_resource_count_controls_skipped{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 17\n# HELP kubescape_resource_count_controls_passed kubescape_resource_count_controls_passed\n# TYPE kubescape_resource_count_controls_passed gauge\nkubescape_resource_count_controls_passed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 0\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.m.String()
			assert.Equal(t, tt.expectedMetrics, actual)
		})
	}
}

func TestMetrics_String_MultiItem_NoDuplicateHeaders(t *testing.T) {
	// Verifies that # HELP and # TYPE headers are emitted exactly once
	// per metric family even when multiple frameworks/controls/resources exist.
	m := Metrics{
		listFrameworks: []mFrameworkComplianceScore{
			{frameworkName: "Framework A", complianceScore: 80, resourcesCountFailed: 5},
			{frameworkName: "Framework B", complianceScore: 60, resourcesCountFailed: 10},
		},
		listControls: []mControlComplianceScore{
			{controlName: "Control A", severity: "high", link: "https://link-a.com", complianceScore: 50},
			{controlName: "Control B", severity: "low", link: "https://link-b.com", complianceScore: 90},
		},
		listResources: []mResources{
			{name: "Resource A", namespace: "ns1", apiVersion: "v1", kind: "Pod", controlsCountFailed: 2},
			{name: "Resource B", namespace: "ns2", apiVersion: "v1", kind: "Pod", controlsCountFailed: 4},
		},
	}

	output := m.String()
	lines := strings.Split(output, "\n")

	// count occurrences of each HELP line
	helpCount := map[string]int{}
	for _, line := range lines {
		if strings.HasPrefix(line, "# HELP ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				helpCount[fields[2]]++
			}
		}
	}

	// every metric family must have exactly one HELP header
	for metricName, count := range helpCount {
		assert.Equal(t, 1, count, "metric family %q has %d # HELP lines, want exactly 1", metricName, count)
	}

	// verify both framework series are present
	assert.Contains(t, output, "kubescape_framework_complianceScore{name=\"Framework A\"} 80")
	assert.Contains(t, output, "kubescape_framework_complianceScore{name=\"Framework B\"} 60")

	// verify both control series are present
	assert.Contains(t, output, "kubescape_control_complianceScore{name=\"Control A\",severity=\"high\",link=\"https://link-a.com\"} 50")
	assert.Contains(t, output, "kubescape_control_complianceScore{name=\"Control B\",severity=\"low\",link=\"https://link-b.com\"} 90")

	// verify both resource series are present
	assert.Contains(t, output, "kubescape_resource_count_controls_failed{apiVersion=\"v1\",kind=\"Pod\",namespace=\"ns1\",name=\"Resource A\"} 2")
	assert.Contains(t, output, "kubescape_resource_count_controls_failed{apiVersion=\"v1\",kind=\"Pod\",namespace=\"ns2\",name=\"Resource B\"} 4")
}

func TestMetrics_String_MultiItem_SamplesGroupedPerFamily(t *testing.T) {
	// The exposition format requires a family's samples to be contiguous. Each item
	// contributes a line to several families, so collecting them item by item and
	// writing them in that order splits every family once there is a second item.
	m := Metrics{
		listFrameworks: []mFrameworkComplianceScore{
			{frameworkName: "Framework A", complianceScore: 80, resourcesCountFailed: 5},
			{frameworkName: "Framework B", complianceScore: 60, resourcesCountFailed: 10},
		},
		listControls: []mControlComplianceScore{
			{controlName: "Control A", severity: "high", link: "https://link-a.com", complianceScore: 50},
			{controlName: "Control B", severity: "low", link: "https://link-b.com", complianceScore: 90},
		},
		listResources: []mResources{
			{name: "Resource A", namespace: "ns1", apiVersion: "v1", kind: "Pod", controlsCountFailed: 2},
			{name: "Resource B", namespace: "ns2", apiVersion: "v1", kind: "Pod", controlsCountFailed: 4},
		},
		listImages: []mImageVulnerability{
			{image: "nginx:latest", severity: "High", cveCount: 3, fixableCVECount: 1},
			{image: "nginx:latest", severity: "Low", cveCount: 7, fixableCVECount: 2},
		},
	}

	// closed records a family that a later sample would reopen: a family is closed
	// once a line belonging to a different family follows it.
	seen := map[string]bool{}
	closed := map[string]bool{}
	current := ""
	for _, line := range strings.Split(m.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		name, _, ok := strings.Cut(line, "{")
		assert.True(t, ok, "sample %q has no labels", line)

		assert.False(t, closed[name], "family %q is split: sample %q comes after another family", name, line)
		if current != "" && current != name {
			closed[current] = true
		}
		seen[name] = true
		current = name
	}

	// the families the fixture populates, so a silently empty output fails too
	for _, name := range []string{
		"kubescape_framework_complianceScore",
		"kubescape_control_complianceScore",
		"kubescape_resource_count_controls_failed",
		"kubescape_resource_count_controls_passed",
		"kubescape_image_count_cve",
		"kubescape_image_count_cve_fixable",
		"kubescape_image_count_cve_kev",
	} {
		assert.True(t, seen[name], "family %q is missing from the output", name)
	}
}

func TestSetComplianceScores_ClusterMetricUsesComplianceScore(t *testing.T) {
	// The cluster gauge is named complianceScore, so it must not be fed the risk score.
	summaryDetails := &reportsummary.SummaryDetails{
		Score:           42,
		ComplianceScore: 77,
	}

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)

	assert.Equal(t, 77, m.rs.complianceScore)
	assert.Contains(t, m.String(), "kubescape_cluster_complianceScore{} 77")
}

func TestSetComplianceScores_ControlMetricsUseComplianceScore(t *testing.T) {
	complianceScore := float32(65)
	summaryDetails := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-SET": {
				ControlID:       "C-SET",
				Name:            "Set Control",
				Score:           10,
				ComplianceScore: &complianceScore,
			},
			"C-UNSET": {
				ControlID: "C-UNSET",
				Name:      "Unset Control",
				Score:     20,
			},
		},
	}

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)
	output := m.String()

	assert.Regexp(t, regexp.MustCompile(`(?m)^kubescape_control_complianceScore\{name="Set Control".*\} 65$`), output)
	assert.NotContains(t, output, "kubescape_control_complianceScore{name=\"Unset Control\"")
	assert.Contains(t, output, "kubescape_control_count_resources_failed{name=\"Unset Control\"")
}

func TestSetComplianceScoresDoNotRoundFractionalScoresToPerfect(t *testing.T) {
	controlScore := float32(99.5)
	summaryDetails := &reportsummary.SummaryDetails{
		ComplianceScore: 99.5,
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name:            "Almost Perfect",
				ComplianceScore: 99.5,
			},
		},
		Controls: reportsummary.ControlSummaries{
			"C-ALMOST": {
				ControlID:       "C-ALMOST",
				Name:            "Almost Perfect Control",
				ComplianceScore: &controlScore,
			},
		},
	}

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)
	output := m.String()

	assert.Contains(t, output, "kubescape_cluster_complianceScore{} 99")
	assert.Contains(t, output, "kubescape_framework_complianceScore{name=\"Almost Perfect\"} 99")
	assert.Regexp(t, regexp.MustCompile(`(?m)^kubescape_control_complianceScore\{name="Almost Perfect Control".*\} 99$`), output)
	assert.NotContains(t, output, "complianceScore{} 100")
}

func TestSetComplianceScores_UnsetFrameworkAndClusterScoresOmitted(t *testing.T) {
	summaryDetails := &reportsummary.SummaryDetails{
		Score:           20,
		ComplianceScore: -1,
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name:            "Unset Framework",
				ComplianceScore: -1,
			},
			{
				Name:            "Set Framework",
				ComplianceScore: 85,
			},
		},
	}

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)
	output := m.String()

	assert.NotContains(t, output, "kubescape_cluster_complianceScore")
	assert.Contains(t, output, "kubescape_cluster_count_resources_failed{} 0")
	assert.NotContains(t, output, "kubescape_framework_complianceScore{name=\"Unset Framework\"")
	assert.Contains(t, output, "kubescape_framework_count_resources_failed{name=\"Unset Framework\"} 0")
	assert.Contains(t, output, "kubescape_framework_complianceScore{name=\"Set Framework\"} 85")
}

func TestSetComplianceScores_NilSummaryDetails(t *testing.T) {
	m := &Metrics{}
	assert.NotPanics(t, func() {
		m.setComplianceScores(nil)
	})
	assert.NotContains(t, m.String(), "kubescape_cluster_complianceScore")
	assert.Empty(t, m.listFrameworks)
	assert.Empty(t, m.listControls)
}

func TestSetComplianceScores_FrameworkNameWhitespaceAndDeduplication(t *testing.T) {
	summaryDetails := &reportsummary.SummaryDetails{
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name:            "  nsa  ",
				ComplianceScore: 80,
			},
			{
				Name:            "nsa",
				ComplianceScore: 85,
			},
			{
				Name:            "   ",
				ComplianceScore: 50,
			},
			{
				Name:            "mitre ",
				ComplianceScore: 90,
			},
		},
	}

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)
	output := m.String()

	// Should trim whitespace and deduplicate identical framework names
	assert.Len(t, m.listFrameworks, 2)
	assert.Equal(t, "mitre", m.listFrameworks[0].frameworkName)
	assert.Equal(t, "nsa", m.listFrameworks[1].frameworkName)
	assert.Equal(t, 85, m.listFrameworks[1].complianceScore)

	// Series should not be duplicated
	assert.Equal(t, 1, strings.Count(output, `kubescape_framework_complianceScore{name="nsa"}`))
	assert.Equal(t, 1, strings.Count(output, `kubescape_framework_complianceScore{name="mitre"}`))
	assert.NotContains(t, output, `name="  nsa  "`)
	assert.NotContains(t, output, `name="   "`)
}

func TestEscapePrometheusLabelValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain string unchanged",
			input:    "nginx-deployment",
			expected: "nginx-deployment",
		},
		{
			name:     "escapes backslash",
			input:    `foo\bar`,
			expected: `foo\\bar`,
		},
		{
			name:     "escapes double quote",
			input:    `foo"bar`,
			expected: `foo\"bar`,
		},
		{
			name:     "escapes newline",
			input:    "foo\nbar",
			expected: `foo\nbar`,
		},
		{
			name:     "neutralizes CRLF to escaped newline",
			input:    "foo\r\nbar",
			expected: `foo\nbar`,
		},
		{
			name:     "neutralizes bare carriage return to escaped newline",
			input:    "foo\rbar",
			expected: `foo\nbar`,
		},
		{
			name:     "neutralizes multiple CR and CRLF sequences",
			input:    "line1\r\nline2\rline3\nline4",
			expected: `line1\nline2\nline3\nline4`,
		},
		{
			name:     "neutralizes CRLF with quotes and backslashes",
			input:    "name=\"evil\"\r\nkubescape_score 100",
			expected: `name=\"evil\"\nkubescape_score 100`,
		},
		{
			name:     "strips null bytes",
			input:    "foo\x00bar",
			expected: "foobar",
		},
		{
			name:     "strips null bytes with crlf and quotes",
			input:    "foo\x00\r\nbar\"test\"",
			expected: `foo\nbar\"test\"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapePrometheusLabelValue(tt.input)
			assert.Equal(t, tt.expected, got)
			assert.NotContains(t, got, "\r", "output must never contain raw carriage returns")
			assert.NotContains(t, got, "\x00", "output must never contain raw null bytes")
		})
	}
}

func TestPrometheusMetrics_CarriageReturnNeutralization(t *testing.T) {
	m := &Metrics{
		listResources: []mResources{
			{
				apiVersion: "v1",
				kind:       "Pod",
				namespace:  "default\r\ninjected",
				name:       "my-pod\rfake-line",
				path:       "manifests/pod\r\n.yaml",
				withPath:   true,
			},
		},
		listImages: []mImageVulnerability{
			{
				image:    "my-image:latest\r\nmalicious",
				platform: "linux/amd64",
				severity: "High",
				cveCount: 1,
			},
		},
	}

	output := m.String()
	assert.NotContains(t, output, "\r", "prometheus metrics output must not contain raw carriage returns")
	assert.Contains(t, output, `namespace="default\ninjected"`)
	assert.Contains(t, output, `name="my-pod\nfake-line"`)
	assert.Contains(t, output, `path="manifests/pod\n.yaml"`)
	assert.Contains(t, output, `image="my-image:latest\nmalicious"`)
}

func TestPrometheusMetrics_NullByteSanitization(t *testing.T) {
	m := &Metrics{
		listResources: []mResources{
			{
				apiVersion: "v1",
				kind:       "Pod",
				namespace:  "default\x00injected",
				name:       "my-pod\x00extra",
				path:       "manifests/pod\x00.yaml",
				withPath:   true,
			},
		},
		listImages: []mImageVulnerability{
			{
				image:    "my-image:latest\x00extra",
				platform: "linux/amd64",
				severity: "High",
				cveCount: 1,
			},
		},
	}

	output := m.String()
	assert.NotContains(t, output, "\x00", "prometheus metrics output must not contain raw null bytes")
	assert.Contains(t, output, `namespace="defaultinjected"`)
	assert.Contains(t, output, `name="my-podextra"`)
	assert.Contains(t, output, `path="manifests/pod.yaml"`)
	assert.Contains(t, output, `image="my-image:latestextra"`)

	parser := expfmt.NewTextParser(model.LegacyValidation)
	_, err := parser.TextToMetricFamilies(strings.NewReader(output))
	require.NoError(t, err, "Prometheus text parser must successfully parse sanitized metrics")
}

type mockCounters struct {
	passed  int
	skipped int
	failed  int
}

func (m *mockCounters) Passed() int   { return m.passed }
func (m *mockCounters) Skipped() int  { return m.skipped }
func (m *mockCounters) Failed() int   { return m.failed }
func (m *mockCounters) Excluded() int { return 0 }
func (m *mockCounters) All() int      { return m.passed + m.skipped + m.failed }

func TestMetricsSet_NilCountersSafety(t *testing.T) {
	t.Run("mComplianceScore nil counters", func(t *testing.T) {
		mrs := mComplianceScore{}
		require.NotPanics(t, func() {
			mrs.set(nil, nil)
		})
		assert.Equal(t, 0, mrs.resourcesCountFailed)
		assert.Equal(t, 0, mrs.resourcesCountPassed)
		assert.Equal(t, 0, mrs.resourcesCountSkipped)
		assert.Equal(t, 0, mrs.controlsCountFailed)
		assert.Equal(t, 0, mrs.controlsCountPassed)
		assert.Equal(t, 0, mrs.controlsCountSkipped)

		resCounters := &mockCounters{passed: 10, skipped: 5, failed: 2}
		require.NotPanics(t, func() {
			mrs.set(resCounters, nil)
		})
		assert.Equal(t, 10, mrs.resourcesCountPassed)
		assert.Equal(t, 5, mrs.resourcesCountSkipped)
		assert.Equal(t, 2, mrs.resourcesCountFailed)
		assert.Equal(t, 0, mrs.controlsCountFailed)

		ctrlCounters := &mockCounters{passed: 8, skipped: 1, failed: 3}
		require.NotPanics(t, func() {
			mrs.set(nil, ctrlCounters)
		})
		assert.Equal(t, 10, mrs.resourcesCountPassed)
		assert.Equal(t, 8, mrs.controlsCountPassed)
		assert.Equal(t, 1, mrs.controlsCountSkipped)
		assert.Equal(t, 3, mrs.controlsCountFailed)
	})

	t.Run("mFrameworkComplianceScore nil counters", func(t *testing.T) {
		mfrs := mFrameworkComplianceScore{}
		require.NotPanics(t, func() {
			mfrs.set(nil, nil)
		})
		assert.Equal(t, 0, mfrs.resourcesCountFailed)
		assert.Equal(t, 0, mfrs.controlsCountFailed)

		resCounters := &mockCounters{passed: 4, skipped: 2, failed: 1}
		require.NotPanics(t, func() {
			mfrs.set(resCounters, nil)
		})
		assert.Equal(t, 4, mfrs.resourcesCountPassed)
		assert.Equal(t, 2, mfrs.resourcesCountSkipped)
		assert.Equal(t, 1, mfrs.resourcesCountFailed)

		ctrlCounters := &mockCounters{passed: 6, skipped: 0, failed: 2}
		require.NotPanics(t, func() {
			mfrs.set(nil, ctrlCounters)
		})
		assert.Equal(t, 4, mfrs.resourcesCountPassed)
		assert.Equal(t, 6, mfrs.controlsCountPassed)
		assert.Equal(t, 0, mfrs.controlsCountSkipped)
		assert.Equal(t, 2, mfrs.controlsCountFailed)
	})

	t.Run("mControlComplianceScore nil counters", func(t *testing.T) {
		mcrs := mControlComplianceScore{}
		require.NotPanics(t, func() {
			mcrs.set(nil)
		})
		assert.Equal(t, 0, mcrs.resourcesCountPassed)
		assert.Equal(t, 0, mcrs.resourcesCountFailed)
		assert.Equal(t, 0, mcrs.resourcesCountSkipped)

		resCounters := &mockCounters{passed: 7, skipped: 3, failed: 1}
		require.NotPanics(t, func() {
			mcrs.set(resCounters)
		})
		assert.Equal(t, 7, mcrs.resourcesCountPassed)
		assert.Equal(t, 3, mcrs.resourcesCountSkipped)
		assert.Equal(t, 1, mcrs.resourcesCountFailed)
	})
}

func TestSetComplianceScores_WithNilCounters(t *testing.T) {
	score := float32(80)
	summaryDetails := &reportsummary.SummaryDetails{
		Score:           80,
		ComplianceScore: 80,
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name:            "FrameworkWithNilCounters",
				ComplianceScore: 80,
			},
		},
		Controls: reportsummary.ControlSummaries{
			"C-0001": {
				ControlID:       "C-0001",
				Name:            "ControlWithNilCounters",
				ComplianceScore: &score,
			},
		},
	}

	m := &Metrics{}
	require.NotPanics(t, func() {
		m.setComplianceScores(summaryDetails)
	})
	assert.Len(t, m.listFrameworks, 1)
	assert.Len(t, m.listControls, 1)
	assert.Equal(t, 0, m.listFrameworks[0].resourcesCountPassed)
	assert.Equal(t, 0, m.listFrameworks[0].controlsCountPassed)
	assert.Equal(t, 0, m.listControls[0].resourcesCountPassed)
}

func TestSetResourcesCountersFromCatalog_NilSummaryDetailsSafety(t *testing.T) {
	resources := map[string]workloadinterface.IMetadata{}
	wl := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "test-pod", "namespace": "default"},
	})
	id := wl.GetID()
	resources[id] = wl

	results := map[string]resourcesresults.Result{
		id: {
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Name: "rule-1",
						},
					},
				},
			},
		},
	}

	catalog := cautils.NewMapResourceCatalog(resources)
	m := &Metrics{}
	require.NotPanics(t, func() {
		m.setResourcesCountersFromCatalog(catalog, results, nil, nil)
	})
	require.Len(t, m.listResources, 1)
	assert.Equal(t, "test-pod", m.listResources[0].name)
}

func TestSetResourcesCountersFromCatalog_DeduplicatesEscapedLabelCollisions(t *testing.T) {
	resources := map[string]workloadinterface.IMetadata{}
	wl1 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "test-pod", "namespace": "default"},
	})
	wl2 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "test-pod\x00", "namespace": "default"},
	})
	id1 := "id-1"
	id2 := "id-2"
	resources[id1] = wl1
	resources[id2] = wl2

	results := map[string]resourcesresults.Result{
		id1: {
			ResourceID: id1,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{Name: "rule-1", Status: "passed"},
					},
				},
			},
		},
		id2: {
			ResourceID: id2,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0002",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{Name: "rule-2", Status: "failed"},
					},
				},
			},
		},
	}

	catalog := cautils.NewMapResourceCatalog(resources)
	m := &Metrics{}
	m.setResourcesCountersFromCatalog(catalog, results, nil, nil)

	require.Len(t, m.listResources, 1)
	assert.Equal(t, 1, m.listResources[0].controlsCountPassed)
	assert.Equal(t, 1, m.listResources[0].controlsCountFailed)

	metricsStr := m.String()
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(metricsStr))
	require.NoError(t, err)
	failedFamily, ok := families["kubescape_resource_count_controls_failed"]
	require.True(t, ok)
	require.Len(t, failedFamily.Metric, 1, "must have exactly 1 series, not duplicate series")
}

func TestSetImageVulnerabilities_NilSummarySafety(t *testing.T) {
	m := &Metrics{isImageScan: true}
	require.NotPanics(t, func() {
		m.setImageVulnerabilities([]cautils.ImageScanData{
			{
				Image:    "test-image:latest",
				Platform: "linux/amd64",
			},
		})
	})
	assert.Empty(t, m.listImages)
}

func TestSetImageVulnerabilities_CanonicalSeverityAndTrimmedLabels(t *testing.T) {
	m := &Metrics{isImageScan: true}
	matches := match.NewMatches(
		mdImageMatch("CVE-2024-0001", " critical ", "openssl", "1.0.0", vulnerability.FixStateFixed),
		mdImageMatch("CVE-2024-0002", "CRITICAL", "curl", "7.0.0", vulnerability.FixStateNotFixed),
	)
	data := cautils.ImageScanData{
		Image:    "  nginx:latest  ",
		Platform: " linux/amd64 ",
		Matches:  matches,
	}
	m.setImageVulnerabilities([]cautils.ImageScanData{data})
	require.Len(t, m.listImages, 1)
	assert.Equal(t, "nginx:latest", m.listImages[0].image)
	assert.Equal(t, "linux/amd64", m.listImages[0].platform)
	assert.Equal(t, "Critical", m.listImages[0].severity)
	assert.Equal(t, 2, m.listImages[0].cveCount)
	assert.Equal(t, 1, m.listImages[0].fixableCVECount)
}
