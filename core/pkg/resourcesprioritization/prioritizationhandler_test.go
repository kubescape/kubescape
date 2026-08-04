package resourcesprioritization

import (
	"context"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

type AttackTracksGetterMock struct{}

func (mock *AttackTracksGetterMock) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	mock_1 := v1alpha1.GetAttackTrackMock(v1alpha1.AttackTrackStep{
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

	mock_2 := v1alpha1.GetAttackTrackMock(v1alpha1.AttackTrackStep{
		Name: "Z",
	})
	mock_3 := v1alpha1.GetAttackTrackMock(v1alpha1.AttackTrackStep{})
	m1 := mock_1.(*v1alpha1.AttackTrack)
	m2 := mock_2.(*v1alpha1.AttackTrack)
	m3 := mock_3.(*v1alpha1.AttackTrack)
	m2.Metadata["name"] = "TestAttackTrack_2"
	m3.Metadata["name"] = "TestAttackTrack_3"
	return []v1alpha1.AttackTrack{*m1, *m2, *m3}, nil
}

func ControlMock(id string, baseScore float32, tags, categories []string) reporthandling.Control {
	return reporthandling.Control{
		ControlID: id,
		BaseScore: baseScore,
		PortalBase: armotypes.PortalBase{
			Attributes: map[string]any{
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
	raw := fmt.Sprintf(`{"apiVersion":"v1","kind":"%s","metadata":{"name":"mock-%s"}}`, kind, kind)
	w, err := workloadinterface.NewWorkload([]byte(raw))
	if err != nil {
		panic(fmt.Sprintf("failed to create workload mock: %v", err))
	}
	return w
}

func DeploymentWorkloadMock(replicas int) workloadinterface.IMetadata {
	var deploymentMock = fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"privileged-deployment","labels":{"app":"nginx"}},"spec":{"replicas":%v,"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"name":"nginx","image":"nginx:1.18.0","ports":[{"containerPort":80}],"securityContext":{"privileged":true}}]}}}}`, replicas)
	w, err := workloadinterface.NewWorkload([]byte(deploymentMock))
	if err != nil {
		panic(fmt.Sprintf("failed to create deployment workload mock: %v", err))
	}
	return w
}

func ResourceAssociatedControlMock(controlID string, status apis.ScanningStatus) resourcesresults.ResourceAssociatedControl {
	control := resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Name: "Test", Status: status},
		},
	}
	control.SetStatus(reporthandling.Control{})
	return control
}

func TestNewResourcesPrioritizationHandler(t *testing.T) {
	handler, err := NewResourcesPrioritizationHandler(context.Background(), &AttackTracksGetterMock{}, false)
	assert.NoError(t, err)
	assert.Len(t, handler.attackTracks, 3)
	assert.Equal(t, handler.attackTracks[0].GetName(), "TestAttackTrack")
	assert.Equal(t, handler.attackTracks[1].GetName(), "TestAttackTrack_2")
	assert.Equal(t, handler.attackTracks[2].GetName(), "TestAttackTrack_3")
	assert.True(t, handler.GetPodTemplateFallback())
	assert.Equal(t, DefaultSupportedKinds(), handler.GetSupportedKinds())
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
			handler, _ := NewResourcesPrioritizationHandler(context.Background(), &AttackTracksGetterMock{}, false)
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

func RolloutWorkloadMock(replicas int) workloadinterface.IMetadata {
	var rolloutMock = fmt.Sprintf(`{"apiVersion":"argoproj.io/v1alpha1","kind":"Rollout","metadata":{"name":"vulnerable-rollout","namespace":"default"},"spec":{"replicas":%v,"template":{"spec":{"containers":[{"name":"web","image":"nginx:1.18.0","securityContext":{"privileged":true}}]}}}}`, replicas)
	w, err := workloadinterface.NewWorkload([]byte(rolloutMock))
	if err != nil {
		panic(fmt.Sprintf("failed to create rollout workload mock: %v", err))
	}
	return w
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

func TestResourcesPrioritizationHandler_ConfigurableSupportedKinds(t *testing.T) {
	handler := &ResourcesPrioritizationHandler{}

	// Default supported kinds check (unset slice)
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Deployment")))
	assert.False(t, handler.isSupportedKind(WorkloadMockWithKind("MyCustomKind")))

	// Add supported kind onto zero-value handler seeds DefaultSupportedKinds
	handler.AddSupportedKinds("MyCustomKind")
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("MyCustomKind")))
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Deployment")), "Deployment should remain supported after AddSupportedKinds on zero-value handler")

	// Override supported kinds
	handler.SetSupportedKinds([]string{"Rollout"})
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Rollout")))
	assert.Contains(t, handler.GetSupportedKinds(), "Rollout")

	// Defensive copy verification on GetSupportedKinds
	kinds := handler.GetSupportedKinds()
	kinds[0] = "MODIFIED"
	assert.NotEqual(t, "MODIFIED", handler.GetSupportedKinds()[0])

	defaultKinds := DefaultSupportedKinds()
	defaultKinds[0] = "MODIFIED"
	assert.NotEqual(t, "MODIFIED", DefaultSupportedKinds()[0])
}

func TestResourcesPrioritizationHandler_DynamicPodTemplateSpecFallback(t *testing.T) {
	handler := &ResourcesPrioritizationHandler{
		podTemplateFallback: true,
	}

	// ArgoCD Rollout with spec.template.spec.containers (not in supportedKinds list)
	rolloutWorkload := RolloutWorkloadMock(2)
	assert.True(t, handler.isSupportedKind(rolloutWorkload), "ArgoCD Rollout manifest with pod template spec should be dynamically detected")

	// Direct spec.containers branch for Pod-shaped custom workload
	podSpecRaw := `{"apiVersion":"v1","kind":"CustomPod","metadata":{"name":"custom-pod"},"spec":{"containers":[{"name":"app","image":"nginx"}]}}`
	customPod, err := workloadinterface.NewWorkload([]byte(podSpecRaw))
	assert.NoError(t, err)
	assert.True(t, handler.isSupportedKind(customPod), "Custom workload with direct spec.containers should be dynamically detected")

	// ConfigMap workload without pod template spec
	configMapYAML := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test-cm"},"data":{"key":"val"}}`
	cmWorkload, err := workloadinterface.NewWorkload([]byte(configMapYAML))
	assert.NoError(t, err)
	assert.False(t, handler.isSupportedKind(cmWorkload), "ConfigMap should not be detected as supported workload")
}

func TestResourcesPrioritizationHandler_PodTemplateFallbackKnobAndScope(t *testing.T) {
	handler := &ResourcesPrioritizationHandler{
		podTemplateFallback: true,
	}

	// Dynamic fallback runs when fallback is enabled
	rolloutWorkload := RolloutWorkloadMock(1)
	assert.True(t, handler.isSupportedKind(rolloutWorkload))

	// Narrow scope with SetSupportedKinds to only "Deployment"
	handler.SetSupportedKinds([]string{"Deployment"})

	// While fallback is true, Rollout is still prioritized due to pod template spec
	assert.True(t, handler.isSupportedKind(rolloutWorkload))

	// Turn fallback off
	handler.SetPodTemplateFallback(false)
	assert.False(t, handler.GetPodTemplateFallback())
	assert.False(t, handler.isSupportedKind(rolloutWorkload), "Rollout should be rejected when fallback is false and not in configured kinds")
	assert.True(t, handler.isSupportedKind(WorkloadMockWithKind("Deployment")), "Deployment should still be supported")

	// Explicitly empty supportedKinds with fallback off
	handler.SetSupportedKinds([]string{})
	assert.False(t, handler.isSupportedKind(WorkloadMockWithKind("Deployment")), "explicitly empty supported kinds should match no kind")
	assert.Empty(t, handler.GetSupportedKinds())

	// Reset to nil (unset -> default kinds)
	handler.SetSupportedKinds(nil)
	assert.Equal(t, DefaultSupportedKinds(), handler.GetSupportedKinds())
}

func TestResourcesPrioritizationHandler_PrioritizeCustomWorkload(t *testing.T) {
	handler, _ := NewResourcesPrioritizationHandler(context.Background(), &AttackTracksGetterMock{}, false)

	allPoliciesControls := map[string]reporthandling.Control{
		"C-001": ControlMock("C-001", 3, []string{"security"}, []string{"D"}),
		"C-002": ControlMock("C-002", 4, []string{"security"}, []string{"B", "C"}),
	}
	results := map[string]resourcesresults.Result{
		"rollout1": {
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedControlMock("C-001", apis.StatusFailed),
				ResourceAssociatedControlMock("C-002", apis.StatusFailed),
			},
		},
	}
	controls := map[string]reportsummary.ControlSummary{
		"C-001": {ControlID: "C-001", ScoreFactor: 3},
		"C-002": {ControlID: "C-002", ScoreFactor: 4},
	}
	resources := map[string]workloadinterface.IMetadata{
		"rollout1": RolloutWorkloadMock(1),
	}

	sessionObj := OPASessionObjMock(allPoliciesControls, results, controls, resources)
	err := handler.PrioritizeResources(sessionObj)
	assert.NoError(t, err)
	assert.Len(t, sessionObj.ResourcesPrioritized, 1, "custom rollout workload should be prioritized")
	assert.Contains(t, sessionObj.ResourcesPrioritized, "rollout1")
}

type AttackTrackControlsLookupMock struct {
	lookup map[string]map[string][]v1alpha1.IAttackTrackControl
}

func (mock *AttackTrackControlsLookupMock) GetAssociatedControls(attackTrack, category string) []v1alpha1.IAttackTrackControl {
	return mock.lookup[attackTrack][category]
}

func (mock *AttackTrackControlsLookupMock) HasAssociatedControls(attackTrack string) bool {
	return len(mock.lookup[attackTrack]) > 0
}

type AttackTrackControlMock struct {
	id         string
	baseScore  float64
	categories []string
}

func (mock *AttackTrackControlMock) GetControlId() string {
	return mock.id
}

func (mock *AttackTrackControlMock) GetScore() float64 {
	return mock.baseScore
}

func (mock *AttackTrackControlMock) GetAttackTrackCategories(attackTrack string) []string {
	return mock.categories
}

func (mock *AttackTrackControlMock) GetControlTypeTags() []string {
	return []string{"security"}
}

func (mock *AttackTrackControlMock) GetSeverity() int {
	return 0
}

func NewAttackTrackControlsLookupMock() *AttackTrackControlsLookupMock {
	return &AttackTrackControlsLookupMock{
		lookup: map[string]map[string][]v1alpha1.IAttackTrackControl{
			"A": {
				"security": {
					&AttackTrackControlMock{id: "C-001", baseScore: 3, categories: []string{"D"}},
					&AttackTrackControlMock{id: "C-002", baseScore: 4, categories: []string{"B", "C"}},
				},
				"compliance": {
					&AttackTrackControlMock{id: "C-003", baseScore: 10, categories: []string{"E"}},
				},
			},
		},
	}
}

func TestResourcesPrioritizationHandler_copyAttackTrack(t *testing.T) {
	handler := &ResourcesPrioritizationHandler{}
	type args struct {
		attackTrack v1alpha1.IAttackTrack
		lookup      v1alpha1.IAttackTrackControlsLookup
	}
	tests := []struct {
		name string
		args args
		want v1alpha1.IAttackTrack
	}{
		{
			name: "copy attack track",
			args: args{
				attackTrack: v1alpha1.GetAttackTrackMock(v1alpha1.AttackTrackStep{
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
				}),
				lookup: NewAttackTrackControlsLookupMock(),
			},
			want: v1alpha1.GetAttackTrackMock(v1alpha1.AttackTrackStep{
				Name: "A",
				SubSteps: []v1alpha1.AttackTrackStep{
					{
						Name: "B",
						SubSteps: []v1alpha1.AttackTrackStep{
							{
								Name:     "C",
								Controls: []v1alpha1.IAttackTrackControl{},
							},
							{
								Name:     "D",
								Controls: []v1alpha1.IAttackTrackControl{},
							},
						},
					},
					{
						Name:     "E",
						Controls: []v1alpha1.IAttackTrackControl{},
					},
				},
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handler.copyAttackTrack(tt.args.attackTrack, tt.args.lookup); got == tt.want {
				t.Errorf("ResourcesPrioritizationHandler.copyAttackTrack() = %v, want %v", got, tt.want)
			}
		})
	}
}
