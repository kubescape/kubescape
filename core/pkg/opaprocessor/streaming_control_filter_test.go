package opaprocessor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// controlIDsInResults collects every control ID that reached the results map.
func controlIDsInResults(opap *OPAProcessor) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, result := range opap.ResourcesResult {
		for _, associated := range result.AssociatedControls {
			ids[associated.GetID()] = struct{}{}
		}
	}
	return ids
}

// TestProcessWithStreaming_HonorsSkipControls runs the eager and streaming
// pipelines over the same manifests with --skip-controls C-0013 and asserts
// both drop the control. ProcessRulesListener applies the filter via
// filterFrameworkControls; ProcessWithStreaming must reach the same verdict,
// otherwise the same cluster is scanned against a different control set once it
// grows past the streaming threshold.
func TestProcessWithStreaming_HonorsSkipControls(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "10000") // eager and streaming both evaluate as one scope

	dir := t.TempDir()
	writeFixtureManifests(t, dir)

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{dir}, SkipControls: "C-0013"}
	handler := resourcehandler.NewFileResourceHandler()
	frameworks := parityFrameworks(true)

	eagerSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	eagerSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	require.NoError(t, resourcehandler.CollectResources(context.Background(), handler, eagerSession, scanInfo))

	eager := NewOPAProcessor(eagerSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	require.NoError(t, eager.ProcessRulesListener(context.Background(), cautils.NewProgressHandler("")))
	require.NotEmpty(t, eager.ResourcesResult)

	streamingSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	streamingSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	batchChan, errChan, expectedBatches, err := handler.StreamResourcesBatches(context.Background(), streamingSession, scanInfo)
	require.NoError(t, err)

	streaming := NewOPAProcessor(streamingSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	streaming.SetInitialResourceCount(0) // file scans never estimate cluster size
	require.NoError(t, streaming.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), expectedBatches))

	eagerControls := controlIDsInResults(eager)
	streamingControls := controlIDsInResults(streaming)
	t.Logf("eager controls: %v", eagerControls)
	t.Logf("streaming controls: %v", streamingControls)

	require.NotContains(t, eagerControls, "C-0013", "eager path must drop the skipped control")
	assert.NotContains(t, streamingControls, "C-0013", "streaming path must drop the skipped control too")
	assert.Equal(t, eagerControls, streamingControls, "both paths must scan the same control set")
}

func failedDependencyTestFramework() []reporthandling.Framework {
	passRule := reporthandling.PolicyRule{
		Rule: `package armo_builtins
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"Pod"},
		}},
	}
	passRule.Name = "pass-rule"

	passingControl := reporthandling.Control{
		ControlID: "C-PASS",
		BaseScore: 5,
		Rules:     []reporthandling.PolicyRule{passRule},
	}
	passingControl.Name = "passing-control"

	failRule := reporthandling.PolicyRule{
		Rule: `package armo_builtins
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{"example.com"},
			APIVersions: []string{"v1"},
			Resources:   []string{"CronTab"},
		}},
	}
	failRule.Name = "crontab-rule"

	excludedControl := reporthandling.Control{
		ControlID: "C-EXCLUDED",
		BaseScore: 5,
		Rules:     []reporthandling.PolicyRule{failRule},
	}
	excludedControl.Name = "excluded-control"

	return []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{Name: "test-fw"},
			Controls:   []reporthandling.Control{passingControl, excludedControl},
		},
	}
}

// TestProcess_ExcludedControlWithFailedGVR_PreservesFilterMembership ensures that
// when an excluded control (via --skip-controls or --include-controls) has a failed
// GVR collection dependency, BuildScanCoverage emitting it as NotEvaluated does NOT
// re-insert it into SummaryDetails.Controls or distort global compliance scoring.
func TestProcess_ExcludedControlWithFailedGVR_PreservesFilterMembership(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "10000")

	dir := t.TempDir()
	manifest := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: clean-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), manifest, 0o600))

	const failedGVR = "example.com/v1/crontabs"

	tests := []struct {
		name     string
		scanInfo *cautils.ScanInfo
	}{
		{
			name: "skip-controls",
			scanInfo: &cautils.ScanInfo{
				InputPatterns: []string{dir},
				SkipControls:  "C-EXCLUDED",
			},
		},
		{
			name: "include-controls",
			scanInfo: &cautils.ScanInfo{
				InputPatterns:   []string{dir},
				IncludeControls: "C-PASS",
			},
		},
	}

	for _, tt := range tests {
		t.Run("eager "+tt.name, func(t *testing.T) {
			handler := resourcehandler.NewFileResourceHandler()
			frameworks := failedDependencyTestFramework()

			eagerSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, tt.scanInfo, nil)
			eagerSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
			require.NoError(t, resourcehandler.CollectResources(context.Background(), handler, eagerSession, tt.scanInfo))

			// Simulate failed dependency collection for C-EXCLUDED
			if eagerSession.ResourceToControlsMap == nil {
				eagerSession.ResourceToControlsMap = make(map[string][]string)
			}
			eagerSession.ResourceToControlsMap[failedGVR] = []string{"C-EXCLUDED"}
			if eagerSession.InfoMap == nil {
				eagerSession.InfoMap = make(map[string]apis.StatusInfo)
			}
			eagerSession.InfoMap[failedGVR] = apis.StatusInfo{
				InnerStatus: apis.StatusSkipped,
				InnerInfo:   "failed to pull CRD",
			}

			eager := NewOPAProcessor(eagerSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
			require.NoError(t, eager.ProcessRulesListener(context.Background(), cautils.NewProgressHandler("")))

			// ScanCoverage properly identifies C-EXCLUDED as not evaluated
			require.NotEmpty(t, eager.ScanCoverage.NotEvaluatedControls)
			assert.Equal(t, "C-EXCLUDED", eager.ScanCoverage.NotEvaluatedControls[0].ControlID)

			// Excluded control must NOT be inserted into SummaryDetails.Controls
			assert.NotContains(t, eager.Report.SummaryDetails.Controls, "C-EXCLUDED", "excluded control must not be reinserted into SummaryDetails.Controls")
			assert.Contains(t, eager.Report.SummaryDetails.Controls, "C-PASS", "selected control must exist in SummaryDetails.Controls")
			assert.Len(t, eager.Report.SummaryDetails.Controls, 1, "SummaryDetails.Controls must only contain selected controls")

			// Global compliance score must not be corrupted by excluded control
			assert.Equal(t, float32(100), eager.Report.SummaryDetails.ComplianceScore, "global score must remain 100%")
			require.Len(t, eager.Report.SummaryDetails.Frameworks, 1)
			assert.Equal(t, float32(100), eager.Report.SummaryDetails.Frameworks[0].ComplianceScore, "framework score must remain 100%")
			assert.NotContains(t, eager.Report.SummaryDetails.Frameworks[0].Controls, "C-EXCLUDED", "excluded control must not be in framework summary")
			assert.Contains(t, eager.Report.SummaryDetails.Frameworks[0].Controls, "C-PASS", "selected control must be in framework summary")
			assert.Len(t, eager.Report.SummaryDetails.Frameworks[0].Controls, 1)
		})

		t.Run("streaming "+tt.name, func(t *testing.T) {
			handler := resourcehandler.NewFileResourceHandler()
			frameworks := failedDependencyTestFramework()

			streamingSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, tt.scanInfo, nil)
			streamingSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

			batchChan, errChan, expectedBatches, err := handler.StreamResourcesBatches(context.Background(), streamingSession, tt.scanInfo)
			require.NoError(t, err)

			// Simulate failed dependency collection for C-EXCLUDED
			if streamingSession.ResourceToControlsMap == nil {
				streamingSession.ResourceToControlsMap = make(map[string][]string)
			}
			streamingSession.ResourceToControlsMap[failedGVR] = []string{"C-EXCLUDED"}
			if streamingSession.InfoMap == nil {
				streamingSession.InfoMap = make(map[string]apis.StatusInfo)
			}
			streamingSession.InfoMap[failedGVR] = apis.StatusInfo{
				InnerStatus: apis.StatusSkipped,
				InnerInfo:   "failed to pull CRD",
			}

			streaming := NewOPAProcessor(streamingSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
			streaming.SetInitialResourceCount(0)
			require.NoError(t, streaming.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), expectedBatches))

			// ScanCoverage properly identifies C-EXCLUDED as not evaluated
			require.NotEmpty(t, streaming.ScanCoverage.NotEvaluatedControls)
			assert.Equal(t, "C-EXCLUDED", streaming.ScanCoverage.NotEvaluatedControls[0].ControlID)

			// Excluded control must NOT be inserted into SummaryDetails.Controls
			assert.NotContains(t, streaming.Report.SummaryDetails.Controls, "C-EXCLUDED", "excluded control must not be reinserted into SummaryDetails.Controls in streaming")
			assert.Contains(t, streaming.Report.SummaryDetails.Controls, "C-PASS", "selected control must exist in SummaryDetails.Controls in streaming")
			assert.Len(t, streaming.Report.SummaryDetails.Controls, 1, "SummaryDetails.Controls must only contain selected controls in streaming")

			// Global compliance score must not be corrupted by excluded control
			assert.Equal(t, float32(100), streaming.Report.SummaryDetails.ComplianceScore, "streaming global score must remain 100%")
			require.Len(t, streaming.Report.SummaryDetails.Frameworks, 1)
			assert.Equal(t, float32(100), streaming.Report.SummaryDetails.Frameworks[0].ComplianceScore, "streaming framework score must remain 100%")
			assert.NotContains(t, streaming.Report.SummaryDetails.Frameworks[0].Controls, "C-EXCLUDED", "excluded control must not be in streaming framework summary")
			assert.Contains(t, streaming.Report.SummaryDetails.Frameworks[0].Controls, "C-PASS", "selected control must be in streaming framework summary")
			assert.Len(t, streaming.Report.SummaryDetails.Frameworks[0].Controls, 1)
		})
	}
}
