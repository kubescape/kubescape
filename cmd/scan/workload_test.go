package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestSetWorkloadScanInfo(t *testing.T) {
	tests := []struct {
		Description  string
		apiVersion   string
		kind         string
		name         string
		namespace    string
		filePath     string
		want         *cautils.ScanInfo
		wantPolicies []cautils.PolicyIdentifier
	}{
		{
			Description: "Set workload scan info",
			kind:        "Deployment",
			name:        "test",
			want: &cautils.ScanInfo{
				ScanType:   cautils.ScanTypeWorkload,
				ScanImages: true,
				ScanObject: &objectsenvelopes.ScanObject{
					Kind: "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name: "test",
					},
				},
			},
			wantPolicies: []cautils.PolicyIdentifier{
				{
					Identifier: "workloadscan",
					Kind:       v1.KindFramework,
				},
				{
					Identifier: "allcontrols",
					Kind:       v1.KindFramework,
				},
			},
		},
		{
			Description: "Set workload scan info with namespace and file path",
			kind:        "Pod",
			name:        "api",
			namespace:   "default",
			filePath:    "manifests/pod.yaml",
			want: &cautils.ScanInfo{
				ScanType:   cautils.ScanTypeWorkload,
				ScanImages: true,
				ScanObject: &objectsenvelopes.ScanObject{
					Kind: "Pod",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name:      "api",
						Namespace: "default",
					},
				},
				InputPatterns: []string{"manifests/pod.yaml"},
			},
			wantPolicies: []cautils.PolicyIdentifier{
				{
					Identifier: "workloadscan",
					Kind:       v1.KindFramework,
				},
				{
					Identifier: "allcontrols",
					Kind:       v1.KindFramework,
				},
			},
		},
		{
			Description: "Set workload scan info with apiVersion",
			apiVersion:  "apps/v1",
			kind:        "Deployment",
			name:        "api",
			namespace:   "default",
			filePath:    "manifests/deployment.yaml",
			want: &cautils.ScanInfo{
				ScanType:   cautils.ScanTypeWorkload,
				ScanImages: true,
				ScanObject: &objectsenvelopes.ScanObject{
					ApiVersion: "apps/v1",
					Kind:       "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name:      "api",
						Namespace: "default",
					},
				},
				InputPatterns: []string{"manifests/deployment.yaml"},
			},
			wantPolicies: []cautils.PolicyIdentifier{
				{
					Identifier: "workloadscan",
					Kind:       v1.KindFramework,
				},
				{
					Identifier: "allcontrols",
					Kind:       v1.KindFramework,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				scanInfo := &cautils.ScanInfo{FilePath: tc.filePath, Namespace: tc.namespace}
				policyIdentifiers := setWorkloadScanInfo(scanInfo, tc.apiVersion, tc.kind, tc.name)

				if scanInfo.ScanType != tc.want.ScanType {
					t.Errorf("got: %v, want: %v", scanInfo.ScanType, tc.want.ScanType)
				}

				if scanInfo.ScanImages != tc.want.ScanImages {
					t.Errorf("got: %v, want: %v", scanInfo.ScanImages, tc.want.ScanImages)
				}

				if scanInfo.ScanObject.Kind != tc.want.ScanObject.Kind {
					t.Errorf("got: %v, want: %v", scanInfo.ScanObject.Kind, tc.want.ScanObject.Kind)
				}

				if scanInfo.ScanObject.Metadata.Name != tc.want.ScanObject.Metadata.Name {
					t.Errorf("got: %v, want: %v", scanInfo.ScanObject.Metadata.Name, tc.want.ScanObject.Metadata.Name)
				}

				if scanInfo.ScanObject.Metadata.Namespace != tc.want.ScanObject.Metadata.Namespace {
					t.Errorf("got: %v, want: %v", scanInfo.ScanObject.Metadata.Namespace, tc.want.ScanObject.Metadata.Namespace)
				}

				assert.Equal(t, tc.want.ScanObject.GetApiVersion(), scanInfo.ScanObject.GetApiVersion())

				if tc.filePath == "" {
					assert.Len(t, scanInfo.InputPatterns, 0)
				} else {
					assert.Equal(t, tc.want.InputPatterns, scanInfo.InputPatterns)
				}

				if len(policyIdentifiers) != len(tc.wantPolicies) {
					t.Errorf("got: %v policy identifiers, want: %v", len(policyIdentifiers), len(tc.wantPolicies))
				}

				for i, wantPolicy := range tc.wantPolicies {
					if i < len(policyIdentifiers) {
						if policyIdentifiers[i].Identifier != wantPolicy.Identifier {
							t.Errorf("got: %v, want: %v", policyIdentifiers[i].Identifier, wantPolicy.Identifier)
						}
						if policyIdentifiers[i].Kind != wantPolicy.Kind {
							t.Errorf("got: %v, want: %v", policyIdentifiers[i].Kind, wantPolicy.Kind)
						}
					}
				}
			},
		)
	}
}

func TestGetWorkloadCmd_ChartPathAndFilePathEmpty(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getWorkloadCmd(mockKubescape, &scanInfo)
	scanInfo.ChartPath = "temp"
	scanInfo.FilePath = ""

	// Verify the command name and short description
	assert.Equal(t, "workload <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]", cmd.Use)
	assert.Equal(t, "Scan a workload for misconfigurations and image vulnerabilities", cmd.Short)
	assert.Equal(t, workloadExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "usage: <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"nginx"})
	expectedErrorMessage = "usage: --chart-path <chart path> --file-path <file path>"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func Test_parseWorkloadIdentifierString_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty identifier",
			input: "",
		},
		{
			name:  "too many segments",
			input: "cluster/default/Deployment/nginx",
		},
		{
			name:  "empty segment",
			input: "default//nginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := parseWorkloadIdentifierString(tt.input)
			assert.Error(t, err)
		})
	}
}

func Test_parseWorkloadIdentifierString_Valid(t *testing.T) {
	t.Run("valid identifier", func(t *testing.T) {
		namespace, kind, name, apiVersion, err := parseWorkloadIdentifierString("default/Deployment/nginx-deployment")
		assert.NoError(t, err)
		assert.Equal(t, "default", namespace)
		assert.Equal(t, "Deployment", kind)
		assert.Equal(t, "nginx-deployment", name)
		assert.Equal(t, "", apiVersion)
	})
}

func Test_parseWorkloadIdentifierString_Values(t *testing.T) {
	testCases := []struct {
		Description    string
		Input          string
		WantNamespace  string
		WantKind       string
		WantName       string
		WantApiVersion string
		WantErr        bool
	}{
		{
			Description:    "valid kind and name",
			Input:          "Deployment/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid namespace kind and name",
			Input:          "default/Deployment/nginx",
			WantNamespace:  "default",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid kind.version and name",
			Input:          "Pod.v1/nginx",
			WantNamespace:  "",
			WantKind:       "Pod",
			WantName:       "nginx",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid kind.version.group and name",
			Input:          "Deployment.v1.apps/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "valid namespace kind.version.group and name",
			Input:          "default/Deployment.v1.apps/nginx",
			WantNamespace:  "default",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "valid multi-label group",
			Input:          "Ingress.v1.networking.k8s.io/name",
			WantNamespace:  "",
			WantKind:       "Ingress",
			WantName:       "name",
			WantApiVersion: "networking.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description: "invalid empty dotted component",
			Input:       "Deployment..apps/nginx",
			WantErr:     true,
		},
		{
			Description: "invalid empty trailing component",
			Input:       "Deployment./nginx",
			WantErr:     true,
		},
		{
			Description: "invalid missing apiVersion",
			Input:       "Deployment.apps/nginx",
			WantErr:     true,
		},
		{
			Description: "invalid apiVersion segment",
			Input:       "Deployment.bogus/nginx",
			WantErr:     true,
		},
		{
			Description: "too many segments",
			Input:       "cluster/default/Deployment/nginx",
			WantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			namespace, kind, name, apiVersion, err := parseWorkloadIdentifierString(tc.Input)
			if tc.WantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.WantNamespace, namespace)
			assert.Equal(t, tc.WantKind, kind)
			assert.Equal(t, tc.WantName, name)
			assert.Equal(t, tc.WantApiVersion, apiVersion)
		})
	}
}
