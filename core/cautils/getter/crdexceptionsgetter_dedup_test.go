package getter

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
)

func TestDeduplicateExceptions(t *testing.T) {
	buildPolicy := func(name, controlID, namespace, kind, workloadName string) armotypes.PostureExceptionPolicy {
		attrs := map[string]string{}
		if namespace != "" {
			attrs[identifiers.AttributeNamespace] = namespace
		}
		if kind != "" {
			attrs[identifiers.AttributeKind] = kind
		}
		if workloadName != "" {
			attrs[identifiers.AttributeName] = workloadName
		}
		return armotypes.PostureExceptionPolicy{
			Name: name,
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
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0001", "team-a", "Deployment", "api"),
			},
			wantNames: []string{"cloud-1"},
		},
		{
			name: "different controls are merged",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0002", "team-a", "Deployment", "api"),
			},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name: "same control different workload is merged",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0001", "team-a", "Deployment", "api"),
			},
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0001", "team-a", "Deployment", "worker"),
			},
			wantNames: []string{"cloud-1", "crd-1"},
		},
		{
			name: "no cloud exceptions keeps all CRD",
			cloud: nil,
			crd: []armotypes.PostureExceptionPolicy{
				buildPolicy("crd-1", "C-0003", "team-b", "StatefulSet", "db"),
			},
			wantNames: []string{"crd-1"},
		},
		{
			name: "no CRD exceptions keeps all cloud",
			cloud: []armotypes.PostureExceptionPolicy{
				buildPolicy("cloud-1", "C-0004", "team-b", "DaemonSet", "agent"),
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
