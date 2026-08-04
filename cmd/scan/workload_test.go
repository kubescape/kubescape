package scan

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	resultshandlingpkg "github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noOpWorkloadPrinter struct{}

func (noOpWorkloadPrinter) PrintNextSteps() {}
func (noOpWorkloadPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) {
}
func (noOpWorkloadPrinter) SetWriter(context.Context, string) {}
func (noOpWorkloadPrinter) Score(float32)                     {}

type workloadScanCaptureKubescape struct {
	mocks.MockIKubescape
	scanInfo *cautils.ScanInfo
}

func (m *workloadScanCaptureKubescape) Scan(scanInfo *cautils.ScanInfo) (*resultshandlingpkg.ResultsHandler, error) {
	m.scanInfo = scanInfo
	results := resultshandlingpkg.NewResultsHandler(nil, nil, noOpWorkloadPrinter{})
	results.SetData(&cautils.OPASessionObj{Report: &reporthandlingv2.PostureReport{}})
	return results, nil
}

func TestSetWorkloadScanInfo(t *testing.T) {
	tests := []struct {
		Description string
		apiVersion  string
		kind        string
		name        string
		namespace   string
		filePath    string
		inputPaths  []string
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
		{
			Description: "Set workload scan info with apiVersion",
			apiVersion:  "apps/v1",
			kind:        "Deployment",
			name:        "api",
			namespace:   "default",
			filePath:    "manifests/deployment.yaml",
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
					ApiVersion: "apps/v1",
					Kind:       "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name:      "api",
						Namespace: "default",
					},
				},
				InputPatterns: []string{"manifests/deployment.yaml"},
			},
		},
		{
			Description: "Set workload scan info preserves positional input paths",
			apiVersion:  "apps/v1",
			kind:        "Deployment",
			name:        "api",
			namespace:   "default",
			filePath:    "manifests/deployment.yaml",
			inputPaths:  []string{"manifests"},
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
					ApiVersion: "apps/v1",
					Kind:       "Deployment",
					Metadata: objectsenvelopes.ScanObjectMetadata{
						Name:      "api",
						Namespace: "default",
					},
				},
				InputPatterns: []string{"manifests"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				scanInfo := &cautils.ScanInfo{FilePath: tc.filePath, Namespace: tc.namespace, InputPatterns: tc.inputPaths}
				setWorkloadScanInfo(scanInfo, tc.apiVersion, tc.kind, tc.name)

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

				if len(tc.want.InputPatterns) == 0 {
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

func TestGetWorkloadCmd_ArgsAcceptsPositionalLocalInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(&mocks.MockIKubescape{}, &scanInfo)

	err := cmd.Args(cmd, []string{"Deployment/nginx", "manifests/app.yaml", "manifests/sidecar.yaml"})

	assert.NoError(t, err)
}

func TestGetWorkloadCmd_ArgsRejectsAmbiguousFilePathAndPositionalInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(&mocks.MockIKubescape{}, &scanInfo)
	scanInfo.FilePath = "manifests/app.yaml"

	err := cmd.Args(cmd, []string{"Deployment/nginx", "manifests"})

	assert.EqualError(t, err, "usage: use either --file-path or positional input paths, not both")
}

func TestGetWorkloadCmd_ArgsAllowsChartPathWithScanRoot(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(&mocks.MockIKubescape{}, &scanInfo)
	scanInfo.ChartPath = "charts/app"
	scanInfo.FilePath = "charts/app/templates/deployment.yaml"

	err := cmd.Args(cmd, []string{"Deployment/nginx", "."})

	assert.NoError(t, err)
}

func TestGetWorkloadCmd_ArgsRejectsStdinMixedWithOtherInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(&mocks.MockIKubescape{}, &scanInfo)

	err := cmd.Args(cmd, []string{"Deployment/nginx", "-", "manifests/app.yaml"})

	assert.EqualError(t, err, "usage: stdin input '-' cannot be combined with other input paths")
}

func TestPrepareWorkloadInput(t *testing.T) {
	t.Run("positional inputs populate input patterns", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}

		cleanup, err := prepareWorkloadInput(bytes.NewBufferString(""), []string{"Deployment/nginx", "manifests/a.yaml", "manifests/b.yaml"}, &scanInfo)
		defer cleanup()

		require.NoError(t, err)
		assert.Equal(t, []string{"manifests/a.yaml", "manifests/b.yaml"}, scanInfo.InputPatterns)
	})

	t.Run("file path flag populates input patterns when no positional input is passed", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{FilePath: "manifests/app.yaml"}

		cleanup, err := prepareWorkloadInput(bytes.NewBufferString(""), []string{"Deployment/nginx"}, &scanInfo)
		defer cleanup()

		require.NoError(t, err)
		assert.Equal(t, []string{"manifests/app.yaml"}, scanInfo.InputPatterns)
	})

	t.Run("stdin input is copied to a temporary manifest and cleaned up", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}
		stdin := bytes.NewBufferString("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx\n")

		cleanup, err := prepareWorkloadInput(stdin, []string{"Pod/nginx", "-"}, &scanInfo)
		require.NoError(t, err)
		require.Len(t, scanInfo.InputPatterns, 1)

		got, err := os.ReadFile(scanInfo.InputPatterns[0])
		require.NoError(t, err)
		assert.Contains(t, string(got), "kind: Pod")

		cleanup()
		_, err = os.Stat(scanInfo.InputPatterns[0])
		assert.True(t, os.IsNotExist(err), "temporary stdin manifest should be removed by cleanup")
	})
}

func TestGetWorkloadCmd_RunE_ForwardsPositionalLocalInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	ks := &workloadScanCaptureKubescape{}
	cmd := getWorkloadCmd(ks, &scanInfo)

	err := cmd.RunE(cmd, []string{"Deployment/nginx", "manifests/app.yaml", "manifests/sidecar.yaml"})

	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	assert.Equal(t, cautils.ScanTypeWorkload, ks.scanInfo.ScanType)
	assert.Equal(t, []string{"manifests/app.yaml", "manifests/sidecar.yaml"}, ks.scanInfo.InputPatterns)
	assert.Equal(t, "Deployment", ks.scanInfo.ScanObject.GetKind())
	assert.Equal(t, "nginx", ks.scanInfo.ScanObject.GetName())
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
