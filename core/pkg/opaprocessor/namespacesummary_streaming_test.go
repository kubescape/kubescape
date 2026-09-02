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

// TestNamespaceSummaries_EagerMatchesStreaming runs the eager and streaming
// pipelines over the same manifests and asserts they build identical
// NamespaceSummaries. Both ProcessRulesListener and ProcessWithStreaming call
// cautils.BuildNamespaceSummaries independently; --skip-controls was found
// wired into only one of these two paths, so this is exactly the class of
// divergence a namespace-scoped feature added here must be tested against.
func TestNamespaceSummaries_EagerMatchesStreaming(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "10000") // eager and streaming both evaluate as one scope

	dir := t.TempDir()
	writeFixtureManifests(t, dir)

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{dir}}
	handler := resourcehandler.NewFileResourceHandler()
	frameworks := parityFrameworks(true)

	eagerSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	eagerSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	require.NoError(t, resourcehandler.CollectResources(context.Background(), handler, eagerSession, scanInfo))

	eager := NewOPAProcessor(eagerSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	require.NoError(t, eager.ProcessRulesListener(context.Background(), cautils.NewProgressHandler("")))
	require.NotEmpty(t, eager.NamespaceSummaries, "the fixture has namespaced resources with failures, so summaries must be built")

	streamingSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	streamingSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	batchChan, errChan, expectedBatches, err := handler.StreamResourcesBatches(context.Background(), streamingSession, scanInfo)
	require.NoError(t, err)

	streaming := NewOPAProcessor(streamingSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	streaming.SetInitialResourceCount(0) // file scans never estimate cluster size
	require.NoError(t, streaming.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), expectedBatches))

	assert.Equal(t, eager.NamespaceSummaries, streaming.NamespaceSummaries)
}
