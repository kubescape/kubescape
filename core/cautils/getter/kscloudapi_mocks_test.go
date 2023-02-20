package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

func mockAttackTracks() []v1alpha1.AttackTrack {
	return []v1alpha1.AttackTrack{
		{
			ApiVersion: "v1",
			Kind:       "track",
			Metadata:   map[string]interface{}{"label": "name"},
			Spec: v1alpha1.AttackTrackSpecification{
				Version:     "v2",
				Description: "a mock",
				Data: v1alpha1.AttackTrackStep{
					Name:        "track1",
					Description: "mock-step",
					SubSteps: []v1alpha1.AttackTrackStep{
						{
							Name:        "track1",
							Description: "mock-step",
							Controls: []v1alpha1.IAttackTrackControl{
								mockControlPtr("control-1"),
							},
						},
					},
					Controls: []v1alpha1.IAttackTrackControl{
						mockControlPtr("control-2"),
						mockControlPtr("control-3"),
					},
				},
			},
		},
		{
			ApiVersion: "v1",
			Kind:       "track",
			Metadata:   map[string]interface{}{"label": "stuff"},
			Spec: v1alpha1.AttackTrackSpecification{
				Version:     "v1",
				Description: "another mock",
				Data: v1alpha1.AttackTrackStep{
					Name:        "track2",
					Description: "mock-step2",
					SubSteps: []v1alpha1.AttackTrackStep{
						{
							Name:        "track3",
							Description: "mock-step",
							Controls: []v1alpha1.IAttackTrackControl{
								mockControlPtr("control-4"),
							},
						},
					},
					Controls: []v1alpha1.IAttackTrackControl{
						mockControlPtr("control-5"),
						mockControlPtr("control-6"),
					},
				},
			},
		},
	}
}

func mockFrameworks() []reporthandling.Framework {
	id1s := []string{"control-1", "control-2"}
	id2s := []string{"control-3", "control-4"}
	id3s := []string{"control-5", "control-6"}

	return []reporthandling.Framework{
		{
			PortalBase: armotypes.PortalBase{
				Name: "mock-1",
			},
			CreationTime: "now",
			Description:  "mock-1",
			Controls: []reporthandling.Control{
				mockControl("control-1"),
				mockControl("control-2"),
			},
			ControlsIDs: &id1s,
			SubSections: map[string]*reporthandling.FrameworkSubSection{
				"section1": {
					ID:         "section-id",
					ControlIDs: id1s,
				},
			},
		},
		{
			PortalBase: armotypes.PortalBase{
				Name: "mock-2",
			},
			CreationTime: "then",
			Description:  "mock-2",
			Controls: []reporthandling.Control{
				mockControl("control-3"),
				mockControl("control-4"),
			},
			ControlsIDs: &id2s,
			SubSections: map[string]*reporthandling.FrameworkSubSection{
				"section2": {
					ID:         "section-id",
					ControlIDs: id2s,
				},
			},
		},
		{
			PortalBase: armotypes.PortalBase{
				Name: "nsa",
			},
			CreationTime: "tomorrow",
			Description:  "nsa mock",
			Controls: []reporthandling.Control{
				mockControl("control-5"),
				mockControl("control-6"),
			},
			ControlsIDs: &id3s,
			SubSections: map[string]*reporthandling.FrameworkSubSection{
				"section2": {
					ID:         "section-id",
					ControlIDs: id3s,
				},
			},
		},
	}
}

func mockControl(controlID string) reporthandling.Control {
	return reporthandling.Control{
		ControlID: controlID,
	}
}
func mockControlPtr(controlID string) *reporthandling.Control {
	val := mockControl(controlID)

	return &val
}

func mockExceptions() []armotypes.PostureExceptionPolicy {
	return []armotypes.PostureExceptionPolicy{
		{
			PolicyType:   "postureExceptionPolicy",
			CreationTime: "now",
			Actions: []armotypes.PostureExceptionPolicyActions{
				"alertOnly",
			},
			Resources: []armotypes.PortalDesignator{
				{
					DesignatorType: "Attributes",
					Attributes: map[string]string{
						"kind":      "Pod",
						"name":      "coredns-[A-Za-z0-9]+-[A-Za-z0-9]+",
						"namespace": "kube-system",
					},
				},
				{
					DesignatorType: "Attributes",
					Attributes: map[string]string{
						"kind":      "Pod",
						"name":      "etcd-.*",
						"namespace": "kube-system",
					},
				},
			},
			PosturePolicies: []armotypes.PosturePolicy{
				{
					FrameworkName: "MITRE",
					ControlID:     "C-.*",
				},
				{
					FrameworkName: "another-framework",
					ControlID:     "a regexp",
				},
			},
		},
		{
			PolicyType:   "postureExceptionPolicy",
			CreationTime: "then",
			Actions: []armotypes.PostureExceptionPolicyActions{
				"alertOnly",
			},
			Resources: []armotypes.PortalDesignator{
				{
					DesignatorType: "Attributes",
					Attributes: map[string]string{
						"kind": "Deployment",
						"name": "my-regexp",
					},
				},
				{
					DesignatorType: "Attributes",
					Attributes: map[string]string{
						"kind": "Secret",
						"name": "another-regexp",
					},
				},
			},
			PosturePolicies: []armotypes.PosturePolicy{
				{
					FrameworkName: "yet-another-framework",
					ControlID:     "a regexp",
				},
			},
		},
	}
}

func mockTenantResponse() *TenantResponse {
	return &TenantResponse{
		TenantID:  "id",
		Token:     "token",
		Expires:   "expiry-time",
		AdminMail: "admin@example.com",
	}
}

func mockCustomerConfig(cluster, scope string) func() *armotypes.CustomerConfig {
	if cluster == "" {
		cluster = "my-cluster"
	}

	if scope == "" {
		scope = "default"
	}

	return func() *armotypes.CustomerConfig {
		return &armotypes.CustomerConfig{
			Name: "user",
			Attributes: map[string]interface{}{
				"label": "value",
			},
			Scope: armotypes.PortalDesignator{
				DesignatorType: "Attributes",
				Attributes: map[string]string{
					"kind":  "Cluster",
					"name":  cluster,
					"scope": scope,
				},
			},
			Settings: armotypes.Settings{
				PostureControlInputs: map[string][]string{
					"inputs-1": {"x1", "y2"},
					"inputs-2": {"x2", "y2"},
				},
				PostureScanConfig: armotypes.PostureScanConfig{
					ScanFrequency: armotypes.ScanFrequency("weekly"),
				},
				VulnerabilityScanConfig: armotypes.VulnerabilityScanConfig{
					ScanFrequency:             armotypes.ScanFrequency("daily"),
					CriticalPriorityThreshold: 1,
					HighPriorityThreshold:     2,
					MediumPriorityThreshold:   3,
					ScanNewDeployment:         true,
					AllowlistRegistries:       []string{"a", "b"},
					BlocklistRegistries:       []string{"c", "d"},
				},
				SlackConfigurations: armotypes.SlackSettings{
					Token: "slack-token",
				},
			},
		}
	}
}

func mockLoginResponse() *FeLoginResponse {
	return &FeLoginResponse{
		Token:        "access-token",
		RefreshToken: "refresh-token",
		Expires:      "expiry-time",
		ExpiresIn:    123,
	}
}
