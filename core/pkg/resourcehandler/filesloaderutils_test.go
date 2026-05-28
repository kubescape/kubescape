package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

// localWorkloadWithPath builds a localworkload with the given source path so its GetID() embeds the path hash.
func localWorkloadWithPath(apiVersion, kind, namespace, name, path string) workloadinterface.IMetadata {
	wl := mockWorkload(apiVersion, kind, namespace, name)
	lw := localworkload.NewLocalWorkload(wl.GetObject())
	lw.SetPath(path)
	return lw
}

func TestProviderRank(t *testing.T) {
	tt := []struct {
		name     string
		fileType string
		expected int
	}{
		{name: "kustomize directory", fileType: reporthandling.SourceTypeKustomizeDirectory, expected: 2},
		{name: "helm chart", fileType: reporthandling.SourceTypeHelmChart, expected: 2},
		{name: "yaml file", fileType: reporthandling.SourceTypeYaml, expected: 1},
		{name: "json file", fileType: reporthandling.SourceTypeJson, expected: 1},
		{name: "empty", fileType: "", expected: 0},
		{name: "unknown", fileType: "something-unknown", expected: 0},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, providerRank(tc.fileType))
		})
	}
}

func TestResourceIdentity(t *testing.T) {
	base := localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "deploy.yaml:0")

	tt := []struct {
		name     string
		other    workloadinterface.IMetadata
		expected bool
	}{
		{
			name:     "same identity different path",
			other:    localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "/some/dir"),
			expected: true,
		},
		{
			name:     "different namespace",
			other:    localWorkloadWithPath("apps/v1", "Deployment", "other", "bad-deploy", "x"),
			expected: false,
		},
		{
			name:     "different name",
			other:    localWorkloadWithPath("apps/v1", "Deployment", "default", "other", "x"),
			expected: false,
		},
		{
			name:     "different kind",
			other:    localWorkloadWithPath("apps/v1", "StatefulSet", "default", "bad-deploy", "x"),
			expected: false,
		},
		{
			name:     "different api version",
			other:    localWorkloadWithPath("v1", "Deployment", "default", "bad-deploy", "x"),
			expected: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expected {
				assert.Equal(t, resourceIdentity(base), resourceIdentity(tc.other))
				assert.NotEqual(t, base.GetID(), tc.other.GetID())
			} else {
				assert.NotEqual(t, resourceIdentity(base), resourceIdentity(tc.other))
			}
		})
	}
}

func TestDedupWorkloads(t *testing.T) {
	raw := localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "deploy.yaml:0")
	rendered := localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "/some/dir")
	helmCopy := localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "/helm")
	kustomizeCopy := localWorkloadWithPath("apps/v1", "Deployment", "default", "bad-deploy", "/kustomize")
	other := localWorkloadWithPath("apps/v1", "Deployment", "default", "other", "other.yaml:0")

	tt := []struct {
		name               string
		workloads          []workloadinterface.IMetadata
		workloadIDToSource map[string]reporthandling.Source
		expectedIDs        []string
	}{
		{
			name:      "rendered copy wins when discovered after raw file",
			workloads: []workloadinterface.IMetadata{raw, rendered},
			workloadIDToSource: map[string]reporthandling.Source{
				raw.GetID():      {FileType: reporthandling.SourceTypeYaml},
				rendered.GetID(): {FileType: reporthandling.SourceTypeKustomizeDirectory},
			},
			expectedIDs: []string{rendered.GetID()},
		},
		{
			name:      "rendered copy wins when discovered before raw file",
			workloads: []workloadinterface.IMetadata{rendered, raw},
			workloadIDToSource: map[string]reporthandling.Source{
				rendered.GetID(): {FileType: reporthandling.SourceTypeKustomizeDirectory},
				raw.GetID():      {FileType: reporthandling.SourceTypeYaml},
			},
			expectedIDs: []string{rendered.GetID()},
		},
		{
			name:      "equal rank keeps the first-seen copy",
			workloads: []workloadinterface.IMetadata{helmCopy, kustomizeCopy},
			workloadIDToSource: map[string]reporthandling.Source{
				helmCopy.GetID():      {FileType: reporthandling.SourceTypeHelmChart},
				kustomizeCopy.GetID(): {FileType: reporthandling.SourceTypeKustomizeDirectory},
			},
			expectedIDs: []string{helmCopy.GetID()},
		},
		{
			name:      "distinct resources are all kept",
			workloads: []workloadinterface.IMetadata{raw, other},
			workloadIDToSource: map[string]reporthandling.Source{
				raw.GetID():   {FileType: reporthandling.SourceTypeYaml},
				other.GetID(): {FileType: reporthandling.SourceTypeYaml},
			},
			expectedIDs: []string{raw.GetID(), other.GetID()},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, gotSrc := dedupWorkloads(tc.workloads, tc.workloadIDToSource)

			assert.Len(t, got, len(tc.expectedIDs))
			assert.Len(t, gotSrc, len(tc.expectedIDs))
			for i, id := range tc.expectedIDs {
				assert.Equal(t, id, got[i].GetID())
				_, ok := gotSrc[id]
				assert.True(t, ok)
			}
		})
	}
}

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
