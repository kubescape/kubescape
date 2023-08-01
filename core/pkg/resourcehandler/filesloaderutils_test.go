package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func mockWorkloadWithSource(apiVersion, kind, namespace, name, source string) workloadinterface.IMetadata {
	wl := mockWorkload(apiVersion, kind, namespace, name)
	resource := reporthandling.NewResourceIMetadata(wl)
	resource.SetSource(&reporthandling.Source{
		Path:         source,
		RelativePath: source,
	})

	return resource
}

func TestFindScanObjectResource(t *testing.T) {
	mappedResources := map[string][]workloadinterface.IMetadata{
		"/v1/pods": {
			mockWorkloadWithSource("v1", "Pod", "default", "nginx", "/fileA.yaml"),
			mockWorkloadWithSource("v1", "Pod", "default", "nginx", "/fileB.yaml"),
			mockWorkloadWithSource("v1", "Pod", "", "mariadb", "/fileB.yaml"),
		},
	}
	tt := []struct {
		name                 string
		scanObject           *objectsenvelopes.ScanObject
		expectedResourceName string
		expectErr            bool
		expectedErrorString  string
	}{
		{
			name:                 "scan object is nil",
			scanObject:           nil,
			expectedResourceName: "",
			expectErr:            false,
		},
		{
			name: "multiple resources match",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Pod",
				ApiVersion: "v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",

					Name: "nginx",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "more than one k8s resource found for '/v1/default/Pod/nginx'",
		},
		{
			name: "single resource match",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Pod",
				ApiVersion: "v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "mariadb",
					Namespace: "",
				},
			},
			expectedResourceName: "mariadb",
			expectErr:            false,
			expectedErrorString:  "",
		},
		{
			name: "no workload match",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deployment",
				ApiVersion: "apps/v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "",
					Name:      "notfound",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "not found",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			resource, err := findScanObjectResource(mappedResources, tc.scanObject)
			if (err != nil) != tc.expectErr {
				t.Errorf("findScanObjectResource() error = %v, expectErr %v", err, tc.expectErr)
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
