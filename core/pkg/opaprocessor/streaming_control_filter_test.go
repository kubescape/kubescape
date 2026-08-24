package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
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
// buildControlExcludedRules; ProcessWithStreaming must reach the same verdict,
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
