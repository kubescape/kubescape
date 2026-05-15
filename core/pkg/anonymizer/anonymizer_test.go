package anonymizer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

// ── Mapping ───────────────────────────────────────────────────────────────────

func TestMapping_GetOrCreate_SameInputReturnsSameOutput(t *testing.T) {
	m := NewMapping()
	first := m.GetOrCreate("res", "my-pod")
	second := m.GetOrCreate("res", "my-pod")
	assert.Equal(t, first, second)
}

func TestMapping_GetOrCreate_DifferentInputsReturnDifferentOutputs(t *testing.T) {
	m := NewMapping()
	a := m.GetOrCreate("res", "pod-a")
	b := m.GetOrCreate("res", "pod-b")
	assert.NotEqual(t, a, b)
}

func TestMapping_GetOrCreate_PrefixIsolation(t *testing.T) {
	m := NewMapping()
	resVal := m.GetOrCreate("res", "myname")
	nsVal := m.GetOrCreate("ns", "myname")
	assert.NotEqual(t, resVal, nsVal)
	assert.Contains(t, resVal, "res-")
	assert.Contains(t, nsVal, "ns-")
}

// ── resolveMappedID ───────────────────────────────────────────────────────────

func TestResolveMappedID_KnownID(t *testing.T) {
	m := NewMapping()
	idMapping := map[string]string{"old-id": "new-id"}
	result := resolveMappedID(m, idMapping, "old-id", "ref")
	assert.Equal(t, "new-id", result)
}

func TestResolveMappedID_UnknownIDFallsBackToMapping(t *testing.T) {
	m := NewMapping()
	idMapping := map[string]string{}
	result := resolveMappedID(m, idMapping, "unknown-id", "ref")
	assert.NotEqual(t, "unknown-id", result)
	assert.Contains(t, result, "ref-")
}

// ── Apply ─────────────────────────────────────────────────────────────────────

func TestApply_NilHandler(t *testing.T) {
	assert.NoError(t, Apply(nil))
}

func TestApply_NilScanData(t *testing.T) {
	rh := &resultshandling.ResultsHandler{}
	assert.NoError(t, Apply(rh))
}

// ── anonymizeSession ──────────────────────────────────────────────────────────

func TestAnonymizeSession_NilSession(t *testing.T) {
	m := NewMapping()
	anonymizeSession(nil, m)
}

func TestAnonymizeSession_NamesAndNamespacesReplaced(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-secret-pod",
			"namespace": "my-secret-ns",
		},
	})

	oldID := pod.GetID()
	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
	}

	m := NewMapping()
	anonymizeSession(session, m)

	for _, r := range session.AllResources {
		assert.NotEqual(t, "my-secret-pod", r.GetName())
		assert.NotEqual(t, "my-secret-ns", r.GetNamespace())
	}
}

// TestAnonymizeSession_IDConsistencyAcrossMaps seeds the same oldID into every
// remapped collection and asserts they all resolve to the same anonymized ID
// after anonymizeSession runs — covering all 6 paths the maintainer requested.
func TestAnonymizeSession_IDConsistencyAcrossMaps(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-pod",
			"namespace": "default",
		},
	})

	oldID := pod.GetID()

	// seed ResourceIDs in a ControlSummary
	resourceIDs := helpersv1.AllLists{}
	resourceIDs.Append(apis.StatusFailed, oldID)

	session := &cautils.OPASessionObj{
		// path 1: AllResources
		AllResources: map[string]workloadinterface.IMetadata{oldID: pod},

		// path 2: ResourcesResult — with nested Paths and RelatedResourcesIDs
		ResourcesResult: map[string]resourcesresults.Result{
			oldID: {
				ResourceID: oldID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name: "rule-1",
								// path 4: Paths[*].ResourceID
								Paths: []armotypes.PosturePaths{
									{ResourceID: oldID},
								},
								// path 5: RelatedResourcesIDs
								RelatedResourcesIDs: []string{oldID},
							},
						},
					},
				},
			},
		},

		// path 3: ResourceSource
		ResourceSource: map[string]reporthandling.Source{
			oldID: {},
		},

		// path 3: ResourcesPrioritized
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			oldID: {ResourceID: oldID},
		},

		// path 3: ResourceAttackTracks
		ResourceAttackTracks: map[string]v1alpha1.IAttackTrack{
			oldID: &v1alpha1.AttackTrack{},
		},

		// path 6: Report.SummaryDetails.Controls[*].ResourceIDs
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": reportsummary.ControlSummary{
						ResourceIDs: resourceIDs,
					},
				},
			},
		},
	}

	m := NewMapping()
	anonymizeSession(session, m)

	// get the new ID from AllResources
	var newID string
	for id := range session.AllResources {
		newID = id
	}
	assert.NotEmpty(t, newID)
	assert.NotEqual(t, oldID, newID, "ID must be anonymized")

	// path 2: ResourcesResult key
	_, inResult := session.ResourcesResult[newID]
	assert.True(t, inResult, "ResourcesResult must use remapped ID as key")

	// path 2: ResourcesResult.ResourceID field
	result := session.ResourcesResult[newID]
	assert.Equal(t, newID, result.ResourceID, "Result.ResourceID must be remapped")

	// path 4: Paths[*].ResourceID
	pathResourceID := result.AssociatedControls[0].ResourceAssociatedRules[0].Paths[0].ResourceID
	assert.Equal(t, newID, pathResourceID, "Paths[*].ResourceID must be remapped")

	// path 5: RelatedResourcesIDs
	relatedID := result.AssociatedControls[0].ResourceAssociatedRules[0].RelatedResourcesIDs[0]
	assert.Equal(t, newID, relatedID, "RelatedResourcesIDs must be remapped")

	// path 3: ResourceSource key
	_, inSource := session.ResourceSource[newID]
	assert.True(t, inSource, "ResourceSource must use remapped ID as key")

	// path 3: ResourcesPrioritized key + field
	prioritized, inPrioritized := session.ResourcesPrioritized[newID]
	assert.True(t, inPrioritized, "ResourcesPrioritized must use remapped ID as key")
	assert.Equal(t, newID, prioritized.ResourceID, "PrioritizedResource.ResourceID must be remapped")

	// path 6: Report.SummaryDetails.Controls ResourceIDs
	control := session.Report.SummaryDetails.Controls["C-0001"]
	allIDs := control.ResourceIDs.All()
	_, found := allIDs[newID]
	assert.True(t, found, "Report.SummaryDetails.Controls ResourceIDs must use remapped ID")

	// path 3: ResourceAttackTracks key
	_, inAttackTracks := session.ResourceAttackTracks[newID]
	assert.True(t, inAttackTracks, "ResourceAttackTracks must use remapped ID as key")
}

func TestAnonymizeSession_LabelsToCopyAreAnonymized(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-pod",
			"namespace": "default",
			"labels": map[string]interface{}{
				"team": "payments",
				"env":  "production",
			},
		},
	})

	oldID := pod.GetID()
	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
		LabelsToCopy:         []string{"team", "env"},
	}

	m := NewMapping()
	anonymizeSession(session, m)

	for _, r := range session.AllResources {
		wl, ok := r.(workloadinterface.IWorkload)
		assert.True(t, ok)
		labels := wl.GetLabels()
		assert.NotEqual(t, "payments", labels["team"], "label value team must be anonymized")
		assert.NotEqual(t, "production", labels["env"], "label value env must be anonymized")
		assert.NotEmpty(t, labels["team"], "label key must still exist")
		assert.NotEmpty(t, labels["env"], "label key must still exist")
	}
}

func TestAnonymizeSession_EmptyLabelsToCopy_LabelsUnchanged(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-pod",
			"namespace": "default",
			"labels": map[string]interface{}{
				"team": "payments",
			},
		},
	})

	oldID := pod.GetID()
	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
		LabelsToCopy:         []string{},
	}

	m := NewMapping()
	anonymizeSession(session, m)

	for _, r := range session.AllResources {
		wl, ok := r.(workloadinterface.IWorkload)
		assert.True(t, ok)
		labels := wl.GetLabels()
		assert.Equal(t, "payments", labels["team"], "label must be unchanged when LabelsToCopy is empty")
	}
}
