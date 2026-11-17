package printer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestPrintNamespaceSummaries_Empty(t *testing.T) {
	var buf bytes.Buffer
	printNamespaceSummaries(&buf, nil)
	assert.Empty(t, buf.String())

	printNamespaceSummaries(&buf, cautils.NamespaceSummaries{})
	assert.Empty(t, buf.String())
}

func TestPrintNamespaceSummaries_Rendering(t *testing.T) {
	tests := []struct {
		name         string
		summaries    cautils.NamespaceSummaries
		expectedRows []string
		notExpect    []string
	}{
		{
			name: "valid compliance scores format with percentage",
			summaries: cautils.NamespaceSummaries{
				{
					Namespace:            "production",
					ComplianceScore:      85.4,
					NonCompliantControls: 3,
					TotalControls:        20,
					ResourceCount:        15,
				},
				{
					Namespace:            "staging",
					ComplianceScore:      100.0,
					NonCompliantControls: 0,
					TotalControls:        20,
					ResourceCount:        10,
				},
				{
					Namespace:            "kube-system",
					ComplianceScore:      0.0,
					NonCompliantControls: 20,
					TotalControls:        20,
					ResourceCount:        8,
				},
			},
			expectedRows: []string{
				"| NAMESPACE | COMPLIANCE SCORE | NON-COMPLIANT CONTROLS | RESOURCES |",
				"| production | 85% | 3/20 | 15 |",
				"| staging | 100% | 0/20 | 10 |",
				"| kube-system | 0% | 20/20 | 8 |",
			},
			notExpect: []string{
				"-1%",
				"N/A",
			},
		},
		{
			name: "uncalculated or negative compliance scores render as N/A",
			summaries: cautils.NamespaceSummaries{
				{
					Namespace:            "uncalculated-ns",
					ComplianceScore:      -1.0,
					NonCompliantControls: 0,
					TotalControls:        0,
					ResourceCount:        5,
				},
				{
					Namespace:            "negative-fraction-ns",
					ComplianceScore:      -0.5,
					NonCompliantControls: 1,
					TotalControls:        5,
					ResourceCount:        2,
				},
				{
					Namespace:            "negative-near-zero-ns",
					ComplianceScore:      -0.25,
					NonCompliantControls: 2,
					TotalControls:        5,
					ResourceCount:        4,
				},
			},
			expectedRows: []string{
				"| uncalculated-ns | N/A | 0/0 | 5 |",
				"| negative-fraction-ns | N/A | 1/5 | 2 |",
				"| negative-near-zero-ns | N/A | 2/5 | 4 |",
			},
			notExpect: []string{
				"-1%",
				"-0%",
				"0%",
			},
		},
		{
			name: "mixed valid and uncalculated scores in single report",
			summaries: cautils.NamespaceSummaries{
				{
					Namespace:            "default",
					ComplianceScore:      -1.0,
					NonCompliantControls: 0,
					TotalControls:        10,
					ResourceCount:        3,
				},
				{
					Namespace:            "workload-ns",
					ComplianceScore:      72.8,
					NonCompliantControls: 4,
					TotalControls:        10,
					ResourceCount:        12,
				},
			},
			expectedRows: []string{
				"| default | N/A | 0/10 | 3 |",
				"| workload-ns | 73% | 4/10 | 12 |",
			},
			notExpect: []string{
				"-1%",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printNamespaceSummaries(&buf, tt.summaries)
			rawOutput := buf.String()

			var normalizedLines []string
			for _, line := range strings.Split(rawOutput, "\n") {
				if trimmed := strings.TrimSpace(line); trimmed != "" {
					normalizedLines = append(normalizedLines, strings.Join(strings.Fields(trimmed), " "))
				}
			}

			for _, expectedRow := range tt.expectedRows {
				assert.Contains(t, normalizedLines, expectedRow)
			}
			for _, notExp := range tt.notExpect {
				assert.NotContains(t, rawOutput, notExp)
			}
		})
	}
}
