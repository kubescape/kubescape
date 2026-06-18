package printer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrometheusPrinter(t *testing.T) {
	// For verbose mode false
	verboseMode := false
	promPrinter := NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)

	// For verbose mode true
	verboseMode = true
	promPrinter = NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)
}

func TestSetWriter(t *testing.T) {
	// Test case 1: Empty outputFile
	outputFile := ""
	promPrinter := &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), outputFile)
	assert.Equal(t, os.Stdout, promPrinter.writer)

	// Test case 2: Valid outputFile
	outputFile = filepath.Join(os.TempDir(), "test.log")
	promPrinter = &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), outputFile)
	f, err := os.Open(outputFile)
	assert.NoError(t, err)
	defer f.Close()
	assert.NotNil(t, promPrinter.writer)
}

func TestScore(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 100\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Score() must write to pp.writer, not stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			promPrinter := NewPrometheusPrinter(false)
			promPrinter.writer = w

			promPrinter.Score(tt.score)

			require.NoError(t, w.Close())
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestResourceMetricsEmitted(t *testing.T) {
	// Regression test for https://github.com/kubescape/kubescape/issues/2236
	// Fails on master (setResourcesCounters commented out), passes with patch.
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	}
	wl := workloadinterface.NewWorkloadObj(obj)
	resourceID := wl.GetID()

	failedRule := resourcesresults.ResourceAssociatedRule{}
	failedRule.SetStatus(apis.StatusFailed, nil)

	skippedRule := resourcesresults.ResourceAssociatedRule{}
	skippedRule.SetStatus(apis.StatusSkipped, nil)

	failedCtrl1 := resourcesresults.ResourceAssociatedControl{}
	failedCtrl1.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{failedRule}

	failedCtrl2 := resourcesresults.ResourceAssociatedControl{}
	failedCtrl2.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{failedRule}

	skippedCtrl := resourcesresults.ResourceAssociatedControl{}
	skippedCtrl.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{skippedRule}

	result := resourcesresults.Result{}
	result.ResourceID = resourceID
	result.AssociatedControls = []resourcesresults.ResourceAssociatedControl{
		failedCtrl1, failedCtrl2, skippedCtrl,
	}

	pp := NewPrometheusPrinter(false)
	metrics := pp.generatePrometheusFormat(
		map[string]workloadinterface.IMetadata{resourceID: wl},
		map[string]resourcesresults.Result{resourceID: result},
		&reportsummary.SummaryDetails{},
	)
	output := metrics.String()

	assert.Contains(t, output, "kubescape_resource_count_controls_failed",
		"missing kubescape_resource_count_controls_failed — setResourcesCounters may be commented out")
	assert.Contains(t, output, "kubescape_resource_count_controls_skipped",
		"missing kubescape_resource_count_controls_skipped — setResourcesCounters may be commented out")
}
