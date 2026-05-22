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
		Description string
		kind        string
		name        string
		namespace   string
		filePath    string
		want        *cautils.ScanInfo
	}{
		{
			Description: "Set workload scan info",
			kind:        "Deployment",
			name:        "test",
			want: &cautils.ScanInfo{
				PolicyIdentifier: []cautils.PolicyIdentifier{
					{
						Identifier: "workloadscan",
						Kind:       v1.KindFramework,
					},
					{
						Identifier: "allcontrols",
						Kind:       v1.KindFramework,
					},
				},
				ScanType:   cautils.ScanTypeWorkload,
				ScanImages: true,
				ScanObject: &objectsenvelopes.ScanObject{
					Kind: "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name: "test",
					},
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
				PolicyIdentifier: []cautils.PolicyIdentifier{
					{
						Identifier: "workloadscan",
						Kind:       v1.KindFramework,
					},
					{
						Identifier: "allcontrols",
						Kind:       v1.KindFramework,
					},
				},
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
		},
	}

	for _, tc := range tests {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				prevNamespace := namespace
				t.Cleanup(func() {
					namespace = prevNamespace
				})
				namespace = tc.namespace

				scanInfo := &cautils.ScanInfo{FilePath: tc.filePath}
				setWorkloadScanInfo(scanInfo, tc.kind, tc.name)

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

				if tc.filePath == "" {
					assert.Len(t, scanInfo.InputPatterns, 0)
				} else {
					assert.Equal(t, tc.want.InputPatterns, scanInfo.InputPatterns)
				}

				if len(scanInfo.PolicyIdentifier) != len(tc.want.PolicyIdentifier) {
					t.Errorf("got: %v policy identifiers, want: %v", len(scanInfo.PolicyIdentifier), len(tc.want.PolicyIdentifier))
				}

				for i, wantPolicy := range tc.want.PolicyIdentifier {
					if i < len(scanInfo.PolicyIdentifier) {
						if scanInfo.PolicyIdentifier[i].Identifier != wantPolicy.Identifier {
							t.Errorf("got: %v, want: %v", scanInfo.PolicyIdentifier[i].Identifier, wantPolicy.Identifier)
						}
						if scanInfo.PolicyIdentifier[i].Kind != wantPolicy.Kind {
							t.Errorf("got: %v, want: %v", scanInfo.PolicyIdentifier[i].Kind, wantPolicy.Kind)
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
	assert.Equal(t, "workload <kind>/<name> [`<glob pattern>`/`-`] [flags]", cmd.Use)
	assert.Equal(t, "Scan a workload for misconfigurations and image vulnerabilities", cmd.Short)
	assert.Equal(t, workloadExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "usage: <kind>/<name> [`<glob pattern>`/`-`] [flags]"
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
			input: "default/Deployment/nginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseWorkloadIdentifierString(tt.input)
			assert.Error(t, err)
		})
	}
}

func Test_parseWorkloadIdentifierString_Valid(t *testing.T) {
	t.Run("valid identifier", func(t *testing.T) {
		kind, name, err := parseWorkloadIdentifierString("default/Deployment")
		assert.NoError(t, err)
		assert.Equal(t, "default", kind)
		assert.Equal(t, "Deployment", name)
	})
}

func Test_parseWorkloadIdentifierString_Values(t *testing.T) {
	testCases := []struct {
		Description string
		Input       string
		WantKind    string
		WantName    string
		WantErr     bool
	}{
		{
			Description: "valid kind and name",
			Input:       "Deployment/nginx",
			WantKind:    "Deployment",
			WantName:    "nginx",
			WantErr:     false,
		},
		{
			Description: "too many segments",
			Input:       "default/Deployment/nginx",
			WantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			kind, name, err := parseWorkloadIdentifierString(tc.Input)
			if tc.WantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.WantKind, kind)
			assert.Equal(t, tc.WantName, name)
		})
	}
}
