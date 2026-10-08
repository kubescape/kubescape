package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Supplemental Namespaces are available to CEL but must never enter the
// report catalog, whose membership drives both total and per-namespace counts.
func TestSupplementalCELNamespaceDoesNotInflateReports(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "eager"
		if streaming {
			name = "streaming"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			namespace := mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"team-a","labels":{"tier":"prod"}}}`)
			pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"web","namespace":"team-a"}}`)
			session := cautils.NewOPASessionObj(ctx, parityFrameworks(true), nil, &cautils.ScanInfo{}, nil)
			session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
			processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

			if streaming {
				resident := cautils.NewResourceBatch(cautils.ClusterScope)
				resident.K8SResources["/v1/pods"] = []string{pod.GetID()}
				resident.AllResources[pod.GetID()] = pod
				resident.CELNamespaceContext = map[string]workloadinterface.IMetadata{namespace.GetID(): namespace}
				batches := make(chan *cautils.ResourceBatch, 1)
				batches <- resident
				close(batches)
				errors := make(chan error)
				close(errors)
				require.NoError(t, processor.ProcessWithStreaming(ctx, batches, errors, cautils.NewProgressHandler(""), 0))
			} else {
				session.K8SResources = cautils.K8SResources{"/v1/pods": {pod.GetID()}}
				session.AllResources = map[string]workloadinterface.IMetadata{pod.GetID(): pod}
				session.CELNamespaceContext = map[string]workloadinterface.IMetadata{namespace.GetID(): namespace}
				processor = NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
				require.NoError(t, processor.ProcessRulesListener(ctx, cautils.NewProgressHandler("")))
			}

			assert.Equal(t, 1, processor.ResourceCount())
			_, inCatalog := processor.GetCatalog().Get(namespace.GetID())
			assert.False(t, inCatalog, "supplemental Namespace must not be a reported resource")
			require.Len(t, processor.NamespaceSummaries, 1)
			assert.Equal(t, "team-a", processor.NamespaceSummaries[0].Namespace)
			assert.Equal(t, 1, processor.NamespaceSummaries[0].ResourceCount)
			assert.NotNil(t, processor.celNamespaceObjectFor(pod.GetObject()))
		})
	}
}
