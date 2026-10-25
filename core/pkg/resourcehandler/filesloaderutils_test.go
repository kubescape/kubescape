package resourcehandler

import (
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
)

// localWorkloadWithPath builds a localworkload with the given source path so its GetID() embeds the path hash.
func localWorkloadWithPath(apiVersion, kind, namespace, name, path string) workloadinterface.IMetadata {
	wl := mockWorkload(apiVersion, kind, namespace, name)
	lw := localworkload.NewLocalWorkload(wl.GetObject())
	lw.SetPath(path)
	return lw
}

func TestFindScanObjectResource(t *testing.T) {
	mappedResources := map[string][]workloadinterface.IMetadata{
		"/v1/pods": {
			localWorkloadWithPath("v1", "Pod", "default", "nginx", "/fileA.yaml"),
			localWorkloadWithPath("v1", "Pod", "default", "nginx", "/fileB.yaml"),
			localWorkloadWithPath("v1", "Pod", "", "mariadb", "/fileB.yaml"),
		},
		"example.com/v1/deploys": {
			localWorkloadWithPath("example.com/v1", "Deploy", "default", "crd-deploy", "/fileC.yaml"),
			localWorkloadWithPath("example.com/v1", "Deploy", "default", "web", "/fileE.yaml"),
		},
		"apps/v1/deployments": {
			localWorkloadWithPath("apps/v1", "Deployment", "default", "nginx", "/fileD.yaml"),
			localWorkloadWithPath("apps/v1", "Deployment", "default", "web", "/fileF.yaml"),
			localWorkloadWithPath("apps/v1", "Deployment", "staging", "staging-only", "/fileG.yaml"),
			localWorkloadWithPath("apps/v1", "Deployment", "", "multi-unnamespaced", "/overlay1.yaml"),
			localWorkloadWithPath("apps/v1", "Deployment", "", "multi-unnamespaced", "/overlay2.yaml"),
		},
		"/v1/secrets": {
			localWorkloadWithPath("v1", "Secret", "default", "my-secret", "/secret.yaml"),
		},
		"/v1/configmaps": {
			localWorkloadWithPath("v1", "ConfigMap", "default", "my-config", "/config.yaml"),
		},
	}
	tt := []struct {
		name                 string
		scanObject           *objectsenvelopes.ScanObject
		expectedResourceName string
		expectedKind         string
		expectedApiVersion   string
		expectErr            bool
		expectedErrorString  string
		expectedSentinel     error
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
			name: "case-insensitive kind match",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "pod",
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
			name: "case-insensitive apiVersion match",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Pod",
				ApiVersion: "V1",
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
			name: "CRD match with PascalCase kind",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deploy",
				ApiVersion: "",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "crd-deploy",
					Namespace: "default",
				},
			},
			expectedResourceName: "crd-deploy",
			expectedKind:         "Deploy",
			expectedApiVersion:   "example.com/v1",
			expectErr:            false,
		},
		{
			name: "CRD match with lowercase alias kind in pass 1",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "deploy",
				ApiVersion: "",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "crd-deploy",
					Namespace: "default",
				},
			},
			expectedResourceName: "crd-deploy",
			expectedKind:         "Deploy",
			expectedApiVersion:   "example.com/v1",
			expectErr:            false,
		},
		{
			name: "built-in resource match via pass 2 alias expansion fallback",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "deploy",
				ApiVersion: "",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "nginx",
					Namespace: "default",
				},
			},
			expectedResourceName: "nginx",
			expectedKind:         "Deployment",
			expectedApiVersion:   "apps/v1",
			expectErr:            false,
		},
		{
			name: "CRD kind takes precedence over built-in alias expansion when names collide",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "deploy",
				ApiVersion: "",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "web",
					Namespace: "default",
				},
			},
			expectedResourceName: "web",
			expectedKind:         "Deploy",
			expectedApiVersion:   "example.com/v1",
			expectErr:            false,
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
			expectedSentinel:     ErrResourceNotFound,
		},
		{
			name: "matched Secret returns ErrSecretScanDenied",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Secret",
				ApiVersion: "v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",
					Name:      "my-secret",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "scanning Secret resources via single resource scan is not supported",
			expectedSentinel:     ErrSecretScanDenied,
		},
		{
			name: "matched non-workload ConfigMap returns ErrNotWorkload",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "ConfigMap",
				ApiVersion: "v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",
					Name:      "my-config",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "is not a valid Kubernetes workload",
			expectedSentinel:     ErrNotWorkload,
		},
		{
			name: "unnamespaced manifest matches default namespace query",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Pod",
				ApiVersion: "v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",
					Name:      "mariadb",
				},
			},
			expectedResourceName: "mariadb",
			expectedKind:         "Pod",
			expectedApiVersion:   "v1",
			expectErr:            false,
		},
		{
			name: "explicit staging workload excluded when default namespace queried",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deployment",
				ApiVersion: "apps/v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",
					Name:      "staging-only",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "not found",
			expectedSentinel:     ErrResourceNotFound,
		},
		{
			name: "explicit staging workload matches when staging namespace queried",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deployment",
				ApiVersion: "apps/v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "staging",
					Name:      "staging-only",
				},
			},
			expectedResourceName: "staging-only",
			expectedKind:         "Deployment",
			expectedApiVersion:   "apps/v1",
			expectErr:            false,
		},
		{
			name: "omitted namespace in file scan matches staging workload",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deployment",
				ApiVersion: "apps/v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "",
					Name:      "staging-only",
				},
			},
			expectedResourceName: "staging-only",
			expectedKind:         "Deployment",
			expectedApiVersion:   "apps/v1",
			expectErr:            false,
		},
		{
			name: "multiple unnamespaced manifests for same resource return ErrAmbiguousResource",
			scanObject: &objectsenvelopes.ScanObject{
				Kind:       "Deployment",
				ApiVersion: "apps/v1",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Namespace: "default",
					Name:      "multi-unnamespaced",
				},
			},
			expectedResourceName: "",
			expectErr:            true,
			expectedErrorString:  "more than one k8s resource found",
			expectedSentinel:     ErrAmbiguousResource,
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
				if tc.expectedSentinel != nil {
					assert.True(t, errors.Is(err, tc.expectedSentinel), "expected error to wrap sentinel %v, got %v", tc.expectedSentinel, err)
				}
			}

			if tc.expectedResourceName != "" {
				assert.Equal(t, tc.expectedResourceName, resource.GetName())
			}
			if tc.expectedKind != "" {
				assert.Equal(t, tc.expectedKind, resource.GetKind())
			}
			if tc.expectedApiVersion != "" {
				assert.Equal(t, tc.expectedApiVersion, resource.GetApiVersion())
			}
		})

	}
}
