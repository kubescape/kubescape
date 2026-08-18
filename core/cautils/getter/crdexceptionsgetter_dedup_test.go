package getter

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
)

func TestDeduplicateExceptions(t *testing.T) {
	buildPolicy := func(name, controlID, namespace, kind, apiGroup, workloadName string) armotypes.PostureExceptionPolicy {
		attrs := map[string]string{}
		if namespace != "" {
			attrs[identifiers.AttributeNamespace] = namespace
		}
		if kind != "" {
			attrs[identifiers.AttributeKind] = kind
		}
		if apiGroup != "" {
			attrs[identifiers.AttributeApiGroup] = apiGroup
		}
		if workloadName != "" {
			attrs[identifiers.AttributeName] = workloadName
		}
		return armotypes.PostureExceptionPolicy{
			PortalBase: armotypes.PortalBase{
				Name: name,
			},
			PosturePolicies: []armotypes.PosturePolicy{
				{ControlID: controlID},
			},
			Resources: []identifiers.PortalDesignator{
				{
					DesignatorType: identifiers.DesignatorAttributes,
					Attributes:     attrs,
				},
			},
		}
	}

	tests := []struct {
		name      string
		cloud     []armotypes.PostureExceptionPolicy
		crd       []armotypes.PostureExceptionPolicy
		wantNames []string
	}{
		{
			name: "cloud wins for same control and workload",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "apps", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0001", "team-a", "Deployment", "apps", "api"),
			},
			wantNames: []string{"cloud-1"},
		},
		{
			name: "different controls are merged",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "apps", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0002", "team-a", "Deployment", "apps", "api"),
			},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name: "same control different workload is merged",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "apps", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0001", "team-a", "Deployment", "apps", "worker"),
			},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name: "same control same workload but different api groups are merged",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "apps", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0001", "team-a", "Deployment", "batch", "api"),
			},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name:  "no cloud exceptions keeps all CRD",
			cloud: nil,
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0003", "team-b", "StatefulSet", "apps", "db"),
			},
			wantNames: []string{"crd-1"},
		},
		{
			name: "no CRD exceptions keeps all cloud",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0004", "team-b", "DaemonSet", "apps", "agent"),
			},
			crd:       nil,
			wantNames: []string{"cloud-1"},
		},
		{
			name:      "empty both",
			cloud:     nil,
			crd:       nil,
			wantNames: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deduplicateExceptions(tc.cloud, tc.crd)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("expected %d exceptions, got %d", len(tc.wantNames), len(got))
			}
			for i, wantName := range tc.wantNames {
				if got[i].Name != wantName {
					t.Fatalf("expected exception %d to be %q, got %q", i, wantName, got[i].Name)
				}
			}
		})
	}
}

func TestDeduplicateExceptionsScopeContainment(t *testing.T) {
	designator := identifiers.PortalDesignator{
		DesignatorType: identifiers.DesignatorAttributes,
		Attributes: map[string]string{
			identifiers.AttributeNamespace: "team-a",
			identifiers.AttributeKind:      "Deployment",
			identifiers.AttributeApiGroup:  "apps",
			identifiers.AttributeName:      "api",
		},
	}
	buildPolicy := func(name string, policy armotypes.PosturePolicy) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: name},
			PosturePolicies: []armotypes.PosturePolicy{policy},
			Resources:       []identifiers.PortalDesignator{designator},
		}
	}

	tests := []struct {
		name      string
		cloud     armotypes.PosturePolicy
		crd       armotypes.PosturePolicy
		wantNames []string
	}{
		{
			name:      "cloud exception for another framework does not suppress the CRD",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "NSA"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "MITRE"},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name:      "framework scoped cloud exception does not suppress a framework wide CRD",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "NSA"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001"},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name:      "framework wide cloud exception suppresses a framework scoped CRD",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "NSA"},
			wantNames: []string{"cloud-1"},
		},
		{
			name:      "framework names are compared case insensitively",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "nsa"},
			crd:       armotypes.PosturePolicy{ControlID: "c-0001", FrameworkName: "NSA"},
			wantNames: []string{"cloud-1"},
		},
		{
			name:      "cloud framework pattern covers the framework it matches",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "MIT.*"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "MITRE"},
			wantNames: []string{"cloud-1"},
		},
		{
			name:      "cloud framework pattern does not cover an unrelated framework",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "MIT.*"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001", FrameworkName: "NSA"},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name:      "rule scoped cloud exception does not suppress the control wide CRD",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", RuleName: "rule-a"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001"},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name:      "rule scoped cloud exception suppresses the same rule from the CRD",
			cloud:     armotypes.PosturePolicy{ControlID: "C-0001", RuleName: "rule-a"},
			crd:       armotypes.PosturePolicy{ControlID: "C-0001", RuleName: "rule-a"},
			wantNames: []string{"cloud-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deduplicateExceptions(
				[]armotypes.PostureExceptionPolicy{buildPolicy("cloud-1", tc.cloud)},
				[]armotypes.PostureExceptionPolicy{buildPolicy("crd-1", tc.crd)},
			)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("expected %d exceptions, got %d", len(tc.wantNames), len(got))
			}
			for i, wantName := range tc.wantNames {
				if got[i].Name != wantName {
					t.Fatalf("expected exception %d to be %q, got %q", i, wantName, got[i].Name)
				}
			}
		})
	}
}
