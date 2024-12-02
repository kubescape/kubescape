package printer

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"} 0", "kubescape_resource_count_controls_skipped{apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"} 0"},
			expectedLabels:  "apiVersion=\"\",kind=\"\",namespace=\"\",name=\"\"",
		},
		{
			name: "Non empty Resource",
			mrc: mResources{
				name:                 "Test Resource",
				namespace:            "Test",
				apiVersion:           "v1",
				kind:                 "Test",
				controlsCountFailed:  7,
				controlsCountSkipped: 7,
			},
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"} 7", "kubescape_resource_count_controls_skipped{apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"} 7"},
			expectedLabels:  "apiVersion=\"v1\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource\"",
		},
		{
			name: "Non empty Resource 2",
			mrc: mResources{
				name:                 "Test Resource 2",
				namespace:            "Test",
				apiVersion:           "v2",
				kind:                 "Test",
				controlsCountFailed:  7,
				controlsCountSkipped: 17,
			},
			expectedMetrics: []string{"kubescape_resource_count_controls_failed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 7", "kubescape_resource_count_controls_skipped{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 17"},
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
			expectedMetrics: "kubescape_cluster_complianceScore{} 0\nkubescape_cluster_count_resources_failed{} 0\nkubescape_cluster_count_resources_skipped{} 0\nkubescape_cluster_count_resources_passed{} 0\nkubescape_cluster_count_control_failed{} 0\nkubescape_cluster_count_control_skipped{} 0\nkubescape_cluster_count_control_passed{} 0\n",
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
			expectedMetrics: "kubescape_cluster_complianceScore{} 0\nkubescape_cluster_count_resources_failed{} 0\nkubescape_cluster_count_resources_skipped{} 0\nkubescape_cluster_count_resources_passed{} 0\nkubescape_cluster_count_control_failed{} 0\nkubescape_cluster_count_control_skipped{} 0\nkubescape_cluster_count_control_passed{} 0\nkubescape_framework_complianceScore{name=\"Test Framework 3\"} 67\nkubescape_framework_count_resources_failed{name=\"Test Framework 3\"} 47\nkubescape_framework_count_resources_skipped{name=\"Test Framework 3\"} 57\nkubescape_framework_count_resources_passed{name=\"Test Framework 3\"} 37\nkubescape_framework_count_control_failed{name=\"Test Framework 3\"} 17\nkubescape_framework_count_control_skipped{name=\"Test Framework 3\"} 27\nkubescape_framework_count_control_passed{name=\"Test Framework 3\"} 7\nkubescape_control_complianceScore{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\nkubescape_control_count_resources_failed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\nkubescape_control_count_resources_skipped{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\nkubescape_control_count_resources_passed{name=\"Test Control\",severity=\"high\",link=\"https://test-link.com\"} 7\nkubescape_resource_count_controls_failed{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 7\nkubescape_resource_count_controls_skipped{apiVersion=\"v2\",kind=\"Test\",namespace=\"Test\",name=\"Test Resource 2\"} 17\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.m.String()
			assert.Equal(t, tt.expectedMetrics, actual)
		})
	}
}
