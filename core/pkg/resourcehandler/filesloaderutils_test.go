package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func mockWorkloadWithSource(apiVersion, kind, namespace, name, ownerReferenceKind, source string) workloadinterface.IMetadata {
	wl := mockWorkload(apiVersion, kind, namespace, name, ownerReferenceKind)
	resource := reporthandling.NewResourceIMetadata(wl)
	resource.SetSource(&reporthandling.Source{
		Path:         source,
		RelativePath: source,
	})

	return resource
}

func TestFindWorkloadToScan(t *testing.T) {
	mappedResources := map[string][]workloadinterface.IMetadata{
		"/v1/pods": {
			mockWorkloadWithSource("v1", "Pod", "default", "nginx", "", "/fileA.yaml"),
			mockWorkloadWithSource("v1", "Pod", "default", "nginx", "", "/fileB.yaml"),
			mockWorkloadWithSource("v1", "Pod", "", "mariadb", "", "/fileB.yaml"),
		},
	}
	tt := []struct {
		name                 string
		workloadIdentifier   *cautils.WorkloadIdentifier
		expectedResourceName string
		expectErr            bool
		expectedErrorString  string
	}{
		{
			name:                 "workload identifier is nil",
			workloadIdentifier:   nil,
			expectedResourceName: "",
			expectErr:            false,
		},
		{
			name: "multiple workloads match",
			workloadIdentifier: &cautils.WorkloadIdentifier{
				Namespace:  "default",
				Kind:       "Pod",
				Name:       "nginx",
				ApiVersion: "v1",
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "more than one workload found for 'Pod/nginx'",
		},
		{
			name: "single workload match",
			workloadIdentifier: &cautils.WorkloadIdentifier{
				Namespace:  "",
				Kind:       "Pod",
				Name:       "mariadb",
				ApiVersion: "v1",
			},
			expectedResourceName: "mariadb",
			expectErr:            false,
			expectedErrorString:  "",
		},
		{
			name: "no workload match",
			workloadIdentifier: &cautils.WorkloadIdentifier{
				Namespace:  "",
				Kind:       "Deployment",
				Name:       "notfound",
				ApiVersion: "apps/v1",
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "not found",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			resource, err := findWorkloadToScan(mappedResources, tc.workloadIdentifier)
			if (err != nil) != tc.expectErr {
				t.Errorf("findWorkloadToScan() error = %v, expectErr %v", err, tc.expectErr)
				return
			}

			if tc.expectErr {
				assert.ErrorContains(t, err, tc.expectedErrorString)
			}

			if tc.expectedResourceName != "" {
				assert.Equal(t, tc.expectedResourceName, resource.GetName())
			}
		})

	}
}
