package resourcesprioritization

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

type AttackTracksGetterMock struct{}

func (mock *AttackTracksGetterMock) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	mock_1 := v1alpha1.AttackTrackMock(v1alpha1.AttackTrackStep{
		Name: "A",
		SubSteps: []v1alpha1.AttackTrackStep{
			{
				Name: "B",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "C",
					},
					{
						Name: "D",
					},
				},
			},
			{
				Name: "E",
			},
		},
	})

	mock_2 := v1alpha1.AttackTrackMock(v1alpha1.AttackTrackStep{
		Name: "Z",
	})
	mock_2.Metadata["name"] = "TestAttackTrack_2"

	return []v1alpha1.AttackTrack{*mock_1, *mock_2}, nil
}

func ControlMock(id string, baseScore float32, tags, categories []string) reporthandling.Control {
	return reporthandling.Control{
		ControlID: id,
		BaseScore: baseScore,
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]interface{}{
				"controlTypeTags": tags,
				"attackTracks": []reporthandling.AttackTrackCategories{
					{
						AttackTrack: "TestAttackTrack",
						Categories:  categories,
					},
				},
			},
		},
	}
}

func OPASessionObjMock(allPoliciesControls map[string]reporthandling.Control, mockResults map[string]resourcesresults.Result, mockControlsSummary map[string]reportsummary.ControlSummary, mockAllResources map[string]workloadinterface.IMetadata) *cautils.OPASessionObj {
	mock := cautils.NewOPASessionObjMock()
	mock.Report.SummaryDetails.Controls = mockControlsSummary
	mock.ResourcesResult = mockResults
	mock.AllResources = mockAllResources
	mock.AllPolicies = cautils.NewPolicies()
	mock.AllPolicies.Controls = allPoliciesControls

	return mock
}

func WorkloadMockWithKind(kind string) workloadinterface.IMetadata {
	mock := workloadinterface.NewWorkloadMock(nil)
	mock.SetKind(kind)
	return mock
}

func DeploymentWorkloadMock(replicas int) workloadinterface.IMetadata {
	var deploymentMock = fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"privileged-deployment","labels":{"app":"nginx"}},"spec":{"replicas":%v,"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"name":"nginx","image":"nginx:1.18.0","ports":[{"containerPort":80}],"securityContext":{"privileged":true}}]}}}}`, replicas)
	w, _ := workloadinterface.NewWorkload([]byte(deploymentMock))
	return w
}

func ResourceAssociatedControlMock(controlID string, status apis.ScanningStatus) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Name: "Test", Status: status},
		},
	}
}

func TestNewResourcesPrioritizationHandler(t *testing.T) {
	handler, err := NewResourcesPrioritizationHandler(&AttackTracksGetterMock{})
	assert.NoError(t, err)
	assert.Len(t, handler.attackTracks, 2)
	assert.Equal(t, handler.attackTracks[0].GetName(), "TestAttackTrack")
	assert.Equal(t, handler.attackTracks[1].GetName(), "TestAttackTrack_2")
}

func TestResourcesPrioritizationHandler_PrioritizeResources(t *testing.T) {
	tests := []struct {
		name                     string
		allPoliciesControls      map[string]reporthandling.Control
		results                  map[string]resourcesresults.Result
		controls                 map[string]reportsummary.ControlSummary
		resources                map[string]workloadinterface.IMetadata
		expectedScores           map[string]float64
		expectedSeverity         map[string]int
		expectedControlsInVector map[string][]string
	}{
		{
			name: "non-empty report",
			allPoliciesControls: map[string]reporthandling.Control{
				"C-001": ControlMock("C-001", 3, []string{"security"}, []string{"D"}),
				"C-002": ControlMock("C-002", 4, []string{"security"}, []string{"B", "C"}),
				"C-003": ControlMock("C-003", 10, []string{"security", "compliance"}, []string{"E"}),
			},
			results: map[string]resourcesresults.Result{
				"resource1": {
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						ResourceAssociatedControlMock("C-001", apis.StatusFailed),
						ResourceAssociatedControlMock("C-002", apis.StatusFailed),
					},
				},
				"resource2": {
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						ResourceAssociatedControlMock("C-001", apis.StatusFailed),
						ResourceAssociatedControlMock("C-002", apis.StatusFailed),
						ResourceAssociatedControlMock("C-003", apis.StatusPassed),
					},
				},
				"resource3": {
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						ResourceAssociatedControlMock("C-001", apis.StatusPassed),
						ResourceAssociatedControlMock("C-002", apis.StatusPassed),
						ResourceAssociatedControlMock("C-003", apis.StatusFailed),
					},
				},
			},
			controls: map[string]reportsummary.ControlSummary{
				"C-001": {
					ControlID:   "C-001",
					ScoreFactor: 3,
				},
				"C-002": {
					ControlID:   "C-002",
					ScoreFactor: 4,
				},
				"C-003": {
					ControlID:   "C-003",
					ScoreFactor: 10,
				},
			},
			resources: map[string]workloadinterface.IMetadata{
				"resource1": DeploymentWorkloadMock(20),
				"resource2": DeploymentWorkloadMock(1),
				"resource3": DeploymentWorkloadMock(1),
			},
			expectedScores: map[string]float64{
				"resource1": float64(84),
				"resource2": float64(30.8),
				"resource3": float64(11),
			},
			expectedSeverity: map[string]int{
				"resource1": apis.SeverityMedium,
				"resource2": apis.SeverityMedium,
				"resource3": apis.SeverityCritical,
			},
			expectedControlsInVector: map[string][]string{
				"resource1": {"C-002", "C-002", "C-002", "C-001"},
				"resource2": {"C-002", "C-002", "C-002", "C-001"},
				"resource3": {"C-003"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _ := NewResourcesPrioritizationHandler(&AttackTracksGetterMock{})
			sessionObj := OPASessionObjMock(tt.allPoliciesControls, tt.results, tt.controls, tt.resources)
			err := handler.PrioritizeResources(sessionObj)
			assert.NoError(t, err, "expected to have no errors in PrioritizeResources()")

			assert.Equalf(t, len(tt.results), len(sessionObj.ResourcesPrioritized), "expected prioritized resources to be not empty")
			for rId, resource := range sessionObj.ResourcesPrioritized {
				expectedScore := tt.expectedScores[rId]
				assert.InDeltaf(t, expectedScore, resource.GetScore(), 0.01, "expected score of resourceID '%s' to be '%v', got '%v'", rId, expectedScore, resource.GetScore())

				expectedSeverity := tt.expectedSeverity[rId]
				assert.Equalf(t, expectedSeverity, resource.GetSeverity(), "expected severity of resourceID '%s' to be '%v', got '%v'", rId, expectedSeverity, resource.GetSeverity())

				expectedControlIDs := tt.expectedControlsInVector[rId]
				assert.ElementsMatchf(t, expectedControlIDs, resource.ListControlsIDs(), "expected controls of resourceID '%s' to be '%v', got '%v'", rId, expectedControlIDs, resource.ListControlsIDs())
			}
		})
	}
}

func TestResourcesPrioritizationHandler_isSupportedKind(t *testing.T) {
	handler := &ResourcesPrioritizationHandler{}
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Deployment")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Pod")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Node")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("DaemonSet")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("StatefulSet")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Job")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("CronJob")))
	assert.False(t, handler.isSupportedKind(nil))
	assert.False(t, handler.isSupportedKind(WorkloadMockWithKind("ConfigMap")))
	assert.False(t, handler.isSupportedKind(WorkloadMockWithKind("ServiceAccount")))
}
