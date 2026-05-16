package anonymizer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
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

type metadataOnly struct{}

func (m *metadataOnly) SetNamespace(string)                {}
func (m *metadataOnly) SetName(string)                     {}
func (m *metadataOnly) SetKind(string)                     {}
func (m *metadataOnly) SetWorkload(map[string]interface{}) {}
func (m *metadataOnly) SetObject(map[string]interface{})   {}
func (m *metadataOnly) SetApiVersion(string)               {}

func (m *metadataOnly) GetNamespace() string                { return "" }
func (m *metadataOnly) GetName() string                     { return "" }
func (m *metadataOnly) GetKind() string                     { return "" }
func (m *metadataOnly) GetApiVersion() string               { return "" }
func (m *metadataOnly) GetWorkload() map[string]interface{} { return nil }
func (m *metadataOnly) GetObject() map[string]interface{}   { return nil }
func (m *metadataOnly) GetID() string                       { return "metadata-only" }

func (m *metadataOnly) GetObjectType() workloadinterface.ObjectType {
	return workloadinterface.ObjectType("metadataOnly")
}

func TestResolveMappedID(t *testing.T) {
	tests := []struct {
		name      string
		idMapping map[string]string
		original  string
		validate  func(t *testing.T, result string)
	}{
		{
			name:      "known id should return mapped value",
			idMapping: map[string]string{"old-id": "new-id"},
			original:  "old-id",
			validate: func(t *testing.T, result string) {
				assert.Equal(t, "new-id", result)
			},
		},
		{
			name:      "unknown id should fall back to generated mapping",
			idMapping: map[string]string{},
			original:  "unknown-id",
			validate: func(t *testing.T, result string) {
				assert.NotEqual(t, "unknown-id", result)
				assert.Contains(t, result, "ref-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()
			result := resolveMappedID(mapping, test.idMapping, test.original, "ref")
			test.validate(t, result)
		})
	}
}

func TestAnonymizeSession_NilSession(t *testing.T) {
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeSession(nil, mapping)
	})
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

	mapping := NewMapping()
	anonymizeSession(session, mapping)

	for _, resource := range session.AllResources {
		assert.NotEqual(t, "my-secret-pod", resource.GetName())
		assert.NotEqual(t, "my-secret-ns", resource.GetNamespace())
		assert.Contains(t, resource.GetName(), "res-")
		assert.Contains(t, resource.GetNamespace(), "ns-")
	}
}

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

	resourceIDs := helpersv1.AllLists{}
	resourceIDs.Append(apis.StatusFailed, oldID)

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			oldID: pod,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			oldID: {
				ResourceID: oldID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name: "rule-1",
								Paths: []armotypes.PosturePaths{
									{ResourceID: oldID},
								},
								RelatedResourcesIDs: []string{oldID},
							},
						},
					},
				},
			},
		},
		ResourceSource: map[string]reporthandling.Source{
			oldID: {},
		},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			oldID: {ResourceID: oldID},
		},
		ResourceAttackTracks: map[string]v1alpha1.IAttackTrack{
			oldID: &v1alpha1.AttackTrack{},
		},
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ResourceIDs: resourceIDs,
					},
				},
			},
		},
	}

	mapping := NewMapping()
	anonymizeSession(session, mapping)

	var newID string
	for id := range session.AllResources {
		newID = id
	}

	assert.NotEmpty(t, newID)
	assert.NotEqual(t, oldID, newID)

	result, ok := session.ResourcesResult[newID]
	assert.True(t, ok)
	assert.Equal(t, newID, result.ResourceID)

	assert.Equal(
		t,
		newID,
		result.AssociatedControls[0].ResourceAssociatedRules[0].Paths[0].ResourceID,
	)

	assert.Equal(
		t,
		newID,
		result.AssociatedControls[0].ResourceAssociatedRules[0].RelatedResourcesIDs[0],
	)

	_, ok = session.ResourceSource[newID]
	assert.True(t, ok)

	prioritized, ok := session.ResourcesPrioritized[newID]
	assert.True(t, ok)
	assert.Equal(t, newID, prioritized.ResourceID)

	control := session.Report.SummaryDetails.Controls["C-0001"]
	_, found := control.ResourceIDs.All()[newID]
	assert.True(t, found)

	_, ok = session.ResourceAttackTracks[newID]
	assert.True(t, ok)
}

func TestAnonymizeSession_LabelHandling(t *testing.T) {
	tests := []struct {
		name         string
		labelsToCopy []string
		validate     func(t *testing.T, labels map[string]string)
	}{
		{
			name:         "selected labels should be anonymized",
			labelsToCopy: []string{"team", "env"},
			validate: func(t *testing.T, labels map[string]string) {
				assert.NotEqual(t, "payments", labels["team"])
				assert.NotEqual(t, "production", labels["env"])
				assert.Contains(t, labels["team"], "lbl-")
				assert.Contains(t, labels["env"], "lbl-")
			},
		},
		{
			name:         "empty labelsToCopy should preserve labels",
			labelsToCopy: []string{},
			validate: func(t *testing.T, labels map[string]string) {
				assert.Equal(t, "payments", labels["team"])
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
				LabelsToCopy:         test.labelsToCopy,
			}

			mapping := NewMapping()
			anonymizeSession(session, mapping)

			for _, resource := range session.AllResources {
				workload, ok := resource.(workloadinterface.IWorkload)
				assert.True(t, ok)
				test.validate(t, workload.GetLabels())
			}
		})
	}
}

func TestAnonymizeResourceLabels_Guards(t *testing.T) {
	tests := []struct {
		name     string
		resource workloadinterface.IMetadata
	}{
		{
			name:     "non workload resource should be ignored",
			resource: &metadataOnly{},
		},
		{
			name:     "workload without labels should be ignored",
			resource: workloadinterface.NewWorkloadMock(nil),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()

			assert.NotPanics(t, func() {
				anonymizeResourceLabels(test.resource, []string{"team"}, mapping)
			})
		})
	}
}
