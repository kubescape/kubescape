package anonymizer

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errInjectedTransform = errors.New("injected transform failure")

type selectiveFailTransformer struct {
	delegate   Transformer
	failPrefix string
	failValue  string
	calls      int
}

func (t *selectiveFailTransformer) Transform(prefix, value string) (string, error) {
	t.calls++
	if prefix == t.failPrefix && value == t.failValue {
		return "", errInjectedTransform
	}
	return t.delegate.Transform(prefix, value)
}

type transactionSnapshot struct {
	Resources              map[string]map[string]any                     `json:"resources"`
	ResourcesResult        map[string]resourcesresults.Result            `json:"resourcesResult"`
	ResourceSource         map[string]reporthandling.Source              `json:"resourceSource"`
	ResourcesPrioritized   map[string]prioritization.PrioritizedResource `json:"resourcesPrioritized"`
	ResourceAttackTrackIDs []string                                      `json:"resourceAttackTrackIds"`
	NamespaceSummaries     cautils.NamespaceSummaries                    `json:"namespaceSummaries"`
	SourcePathsAnonymized  bool                                          `json:"sourcePathsAnonymized"`
}

func snapshotTransformState(t *testing.T, session *cautils.OPASessionObj) []byte {
	t.Helper()
	resources := make(map[string]map[string]any)
	for id, resource := range session.GetCatalog().All() {
		resources[id] = resource.GetObject()
	}
	attackTrackIDs := make([]string, 0, len(session.ResourceAttackTracks))
	for id := range session.ResourceAttackTracks {
		attackTrackIDs = append(attackTrackIDs, id)
	}
	snapshot := transactionSnapshot{
		Resources:              resources,
		ResourcesResult:        session.ResourcesResult,
		ResourceSource:         session.ResourceSource,
		ResourcesPrioritized:   session.ResourcesPrioritized,
		ResourceAttackTrackIDs: attackTrackIDs,
		NamespaceSummaries:     session.NamespaceSummaries,
		SourcePathsAnonymized:  session.SourcePathsAnonymized,
	}
	raw, err := json.Marshal(snapshot)
	require.NoError(t, err)
	return raw
}

func transactionalSessionFixture() (*cautils.OPASessionObj, workloadinterface.IMetadata) {
	first := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"sourcePath": "/manifests/first.yaml:7",
		"metadata": map[string]any{
			"name":      "first-pod",
			"namespace": "workloads",
			"annotations": map[string]any{
				"owner": "payments-team",
			},
			"labels": map[string]any{"team": "payments"},
		},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "api",
				"image": "registry.example/payments:latest",
			}},
		},
	})
	second := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "second-pod",
			"namespace": "workloads",
		},
	})
	firstID := first.GetID()
	secondID := second.GetID()
	orphanID := "apps/v1/workloads/Deployment/orphan-id"

	return &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			firstID:  first,
			secondID: second,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			firstID: {
				ResourceID: firstID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
					ControlID: "C-1",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
						Name:                "rule-one",
						RelatedResourcesIDs: []string{orphanID},
					}},
				}},
			},
		},
		ResourceSource: map[string]reporthandling.Source{
			firstID: {Path: "/secret/path", RelativePath: "deploy/first.yaml"},
		},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			firstID: {ResourceID: firstID},
		},
		ResourceAttackTracks: map[string][]v1alpha1.IAttackTrack{
			firstID: {&v1alpha1.AttackTrack{}},
		},
		NamespaceSummaries: cautils.NamespaceSummaries{
			{Namespace: "summary-only", ComplianceScore: 73},
		},
		LabelsToCopy: []string{"team"},
	}, first
}

func TestTransformSessionRollsBackEveryFailureStage(t *testing.T) {
	tests := []struct {
		name       string
		failPrefix string
		failValue  string
	}{
		{
			name:       "resource metadata",
			failPrefix: "res",
			failValue:  "first-pod",
		},
		{
			name:       "later resource after an earlier resource changed",
			failPrefix: "res",
			failValue:  "second-pod",
		},
		{
			name:       "orphan result reference after catalog rebuild",
			failPrefix: "ref",
			failValue:  "apps/v1/workloads/Deployment/orphan-id",
		},
		{
			name:       "source path after result remapping",
			failPrefix: "src",
			failValue:  "/secret/path",
		},
		{
			name:       "namespace summary at final stage",
			failPrefix: "ns",
			failValue:  "summary-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, originalResource := transactionalSessionFixture()
			before := snapshotTransformState(t, session)
			originalObjectBefore, err := json.Marshal(originalResource.GetObject())
			require.NoError(t, err)
			transformer := &selectiveFailTransformer{
				delegate:   NewMappingTransformer(),
				failPrefix: tt.failPrefix,
				failValue:  tt.failValue,
			}

			err = transformSession(session, NewMapping(), transformer)

			require.ErrorIs(t, err, errInjectedTransform)
			assert.Positive(t, transformer.calls)
			assert.JSONEq(t, string(before), string(snapshotTransformState(t, session)))
			originalObjectAfter, marshalErr := json.Marshal(originalResource.GetObject())
			require.NoError(t, marshalErr)
			assert.JSONEq(t, string(originalObjectBefore), string(originalObjectAfter),
				"resources held by the caller must not be mutated before commit")
		})
	}
}

func TestTransformSessionCommitsCompleteWorkingCopy(t *testing.T) {
	session, originalResource := transactionalSessionFixture()
	originalObject, err := json.Marshal(originalResource.GetObject())
	require.NoError(t, err)

	require.NoError(t, transformSession(session, NewMapping(), NewMappingTransformer()))

	assert.True(t, session.SourcePathsAnonymized)
	assert.Len(t, session.AllResources, 2)
	for oldID, resource := range session.AllResources {
		assert.NotContains(t, oldID, "first-pod")
		assert.NotContains(t, oldID, "second-pod")
		assert.NotContains(t, resource.GetName(), "-pod")
		assert.Contains(t, resource.GetName(), "res-")
	}
	for id, result := range session.ResourcesResult {
		assert.Equal(t, id, result.ResourceID)
		assert.NotContains(t, id, "first-pod")
	}
	for id, source := range session.ResourceSource {
		assert.NotContains(t, id, "first-pod")
		assert.NotEqual(t, "/secret/path", source.Path)
	}
	assert.NotEqual(t, "summary-only", session.NamespaceSummaries[0].Namespace)

	// Existing callers may retain workload pointers outside the session. They
	// see the transformed object only after the full transaction succeeds.
	originalObjectAfter, err := json.Marshal(originalResource.GetObject())
	require.NoError(t, err)
	assert.NotEqual(t, string(originalObject), string(originalObjectAfter))
	assert.Contains(t, originalResource.GetName(), "res-")
}

func TestTransformSessionRejectsNilTransformerWithoutMutation(t *testing.T) {
	session, _ := transactionalSessionFixture()
	before := snapshotTransformState(t, session)

	err := transformSession(session, NewMapping(), nil)

	require.EqualError(t, err, "transformer is required")
	assert.JSONEq(t, string(before), string(snapshotTransformState(t, session)))
}

func TestCloneCatalogRejectsResourceWithoutObject(t *testing.T) {
	catalog := cautils.NewMapResourceCatalog()
	catalog.Add(&metadataOnly{})

	cloned, originals, err := cloneCatalog(catalog)

	assert.Nil(t, cloned)
	assert.Nil(t, originals)
	require.EqualError(t, err, `clone resource "metadata-only": object is unavailable`)
}

func TestCloneCatalogDoesNotShareNestedMaps(t *testing.T) {
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "shared-map-check",
			"namespace": "default",
			"annotations": map[string]any{
				"sensitive": "original",
			},
		},
	})
	catalog := cautils.NewMapResourceCatalog(map[string]workloadinterface.IMetadata{resource.GetID(): resource})

	cloned, originals, err := cloneCatalog(catalog)
	require.NoError(t, err)
	assert.Len(t, originals, 1)
	clonedResource := cloned[resource.GetID()]
	clonedObject := clonedResource.GetObject()
	clonedObject["metadata"].(map[string]any)["annotations"].(map[string]any)["sensitive"] = "changed"
	clonedResource.SetObject(clonedObject)

	originalAnnotation := resource.GetObject()["metadata"].(map[string]any)["annotations"].(map[string]any)["sensitive"]
	assert.Equal(t, "original", originalAnnotation)
}
