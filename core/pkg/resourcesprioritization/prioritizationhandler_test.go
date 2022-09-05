package resourcesprioritization

import (
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

func OPASessionObjMock(mockResults map[string]resourcesresults.Result, mockControlsSummary map[string]reportsummary.ControlSummary, mockAllResources map[string]workloadinterface.IMetadata) *cautils.OPASessionObj {
	mock := cautils.NewOPASessionObjMock()
	mock.Report.SummaryDetails.Controls = mockControlsSummary
	mock.ResourcesResult = mockResults
	mock.AllResources = mockAllResources
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

func TestResourcesPrioritizationHandler_PrioritizeResources(t *testing.T) {
	tests := []struct {
		name                     string
		results                  map[string]resourcesresults.Result
		controls                 map[string]reportsummary.ControlSummary
		resources                map[string]workloadinterface.IMetadata
		expectedScores           map[string]float64
		expectedSeverity         map[string]int
		expectedControlsInVector map[string][]string
	}{
		{
			name: "non-empty report",
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
				"resource1": float64(11),
				"resource2": float64(7.199999999999999),
				"resource3": float64(10.1),
			},
			expectedSeverity: map[string]int{
				"resource1": apis.SeverityMedium,
				"resource2": apis.SeverityMedium,
				"resource3": apis.SeverityCritical,
			},
			expectedControlsInVector: map[string][]string{
				"resource1": {"C-001", "C-002"},
				"resource2": {"C-001", "C-002"},
				"resource3": {"C-003"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &ResourcesPrioritizationHandler{
				skipZeroScores: false,
			}
			sessionObj := OPASessionObjMock(tt.results, tt.controls, tt.resources)
			err := handler.PrioritizeResources(sessionObj)
			assert.NoError(t, err, "expected to have no errors in PrioritizeResources()")

			assert.Equalf(t, len(tt.results), len(sessionObj.ResourcesPrioritized), "expected prioritized resources to be not empty")
			for rId, resource := range sessionObj.ResourcesPrioritized {
				expectedScore := tt.expectedScores[rId]
				assert.Equalf(t, expectedScore, resource.GetScore(), "expected score of resourceID '%s' to be '%v', got '%v'", rId, expectedScore, resource.GetScore())

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
