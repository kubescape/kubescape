package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noOpWorkloadPrinter struct{}

func (noOpWorkloadPrinter) PrintNextSteps() {}
func (noOpWorkloadPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return nil
}
func (noOpWorkloadPrinter) SetWriter(context.Context, string) error { return nil }
func (noOpWorkloadPrinter) Score(float32)                           {}

type workloadScanCaptureKubescape struct {
	mocks.MockIKubescape
	scanInfo *cautils.ScanInfo
}

func (m *workloadScanCaptureKubescape) Scan(scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.scanInfo = scanInfo
	results := resultshandling.NewResultsHandler(nil, nil, noOpWorkloadPrinter{})
	results.SetData(&cautils.OPASessionObj{Report: &reporthandlingv2.PostureReport{}})
	return results, nil
}

func (m *workloadScanCaptureKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return m.Scan(scanInfo, policyIdentifiers)
}

func TestSetWorkloadScanInfo(t *testing.T) {
	tests := []struct {
		Description  string
		kind         string
		name         string
		namespace    string
		filePath     string
		inputPaths   []string
		apiVersion   string
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
			apiVersion:  "",
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
		{
			Description: "Set workload scan info with API version",
			kind:        "Deployment",
			name:        "test",
			apiVersion:  "apps/v1",
			want: &cautils.ScanInfo{
				ScanType:   cautils.ScanTypeWorkload,
				ScanImages: true,
				ScanObject: &objectsenvelopes.ScanObject{
					ApiVersion: "apps/v1",
					Kind:       "Deployment",
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
			Description: "Set workload scan info preserves positional input paths",
			apiVersion:  "apps/v1",
			kind:        "Deployment",
			name:        "api",
			namespace:   "default",
			filePath:    "manifests/deployment.yaml",
			inputPaths:  []string{"manifests"},
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
				InputPatterns: []string{"manifests"},
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
				scanInfo := &cautils.ScanInfo{FilePath: tc.filePath, Namespace: tc.namespace, InputPatterns: tc.inputPaths}
				policyIdentifiers := setWorkloadScanInfo(scanInfo, tc.kind, tc.name, tc.apiVersion)

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

				if scanInfo.ScanObject.GetApiVersion() != tc.apiVersion {
					t.Errorf("got apiVersion: %v, want: %v", scanInfo.ScanObject.GetApiVersion(), tc.apiVersion)
				}

				if len(tc.want.InputPatterns) == 0 {
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

func TestGetWorkloadCmd_FilePathWithoutChartPath(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getWorkloadCmd(mockKubescape, &scanInfo)
	scanInfo.ChartPath = ""
	scanInfo.FilePath = "manifests/app.yaml"

	// Should not return an error when FilePath is set without ChartPath
	err := cmd.Args(cmd, []string{"Deployment/nginx"})
	assert.NoError(t, err)
}

func TestGetWorkloadCmd_RejectsFilePathWithPositionalInputPath(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getWorkloadCmd(mockKubescape, &scanInfo)
	require.NoError(t, cmd.PersistentFlags().Set("chart-path", "./chart"))
	require.NoError(t, cmd.PersistentFlags().Set("file-path", "./chart/templates/deployment.yaml"))

	err := cmd.Args(&cobra.Command{}, []string{"Deployment/nginx", "./manifests"})

	assert.EqualError(t, err, "usage: use either --file-path or positional input paths, not both")
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

func TestGetWorkloadCmd_ArgsRejectsChartPathFilePathAndPositionalInputs(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(&mocks.MockIKubescape{}, &scanInfo)
	scanInfo.ChartPath = "charts/app"
	scanInfo.FilePath = "charts/app/templates/deployment.yaml"

	err := cmd.Args(cmd, []string{"Deployment/nginx", "."})

	assert.EqualError(t, err, "usage: use either --file-path or positional input paths, not both")
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
		assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(scanInfo.InputPatterns[0]))

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

type fakePrinter struct{}

func (p *fakePrinter) PrintNextSteps() {}
func (p *fakePrinter) ActionPrint(ctx context.Context, _ *cautils.OPASessionObj, _ []cautils.ImageScanData) error {
	return nil
}
func (p *fakePrinter) SetWriter(ctx context.Context, _ string) error { return nil }
func (p *fakePrinter) Score(_ float32)                               {}

type recordingKubescape struct {
	mocks.MockIKubescape
	captured *cautils.ScanInfo
}

func (m *recordingKubescape) Scan(scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.captured = scanInfo
	rh := resultshandling.NewResultsHandler(nil, []printer.IPrinter{&fakePrinter{}}, &fakePrinter{})
	rh.SetData(cautils.NewOPASessionObjMock())
	return rh, nil
}

func (m *recordingKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return m.Scan(scanInfo, policyIdentifiers)
}

func TestGetWorkloadCmd_ApiVersion(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantApiVersion string
	}{
		{
			name:           "explicit flag used",
			args:           []string{"--api-version", "apps/v1", "Deployment/nginx"},
			wantApiVersion: "apps/v1",
		},
		{
			name:           "parsed identifier used when no flag",
			args:           []string{"Deployment.v1.apps/nginx"},
			wantApiVersion: "apps/v1",
		},
		{
			name:           "flag wins over parsed identifier",
			args:           []string{"--api-version", "custom/v2", "Deployment.v1.apps/nginx"},
			wantApiVersion: "custom/v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{}
			mock := &recordingKubescape{}
			cmd := getWorkloadCmd(mock, scanInfo)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.NoError(t, err)
			assert.NotNil(t, mock.captured)
			assert.Equal(t, tt.wantApiVersion, mock.captured.ScanObject.GetApiVersion())
		})
	}
}

func TestGetWorkloadCmd_ValidatesImageOptionsAfterEnablingImageScan(t *testing.T) {
	tests := []struct {
		name     string
		scanInfo cautils.ScanInfo
		wantErr  string
	}{
		{
			name: "invalid platform is rejected before scan",
			scanInfo: cautils.ScanInfo{
				ImagePlatform: "win/arm/v7",
			},
			wantErr: "invalid image platform",
		},
		{
			name: "unscoped token is rejected before scan",
			scanInfo: cautils.ScanInfo{
				RegistryToken: "token",
			},
			wantErr: "registry authority",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := tt.scanInfo
			mock := &recordingKubescape{}
			cmd := getWorkloadCmd(mock, &scanInfo)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"Deployment/nginx"})

			err := cmd.Execute()

			require.ErrorContains(t, err, tt.wantErr)
			assert.True(t, scanInfo.ScanImages, "workload setup must enable image scanning before validation")
			assert.Nil(t, mock.captured, "Kubescape.Scan must not run after invalid image options")
		})
	}
}

func TestGetWorkloadCmd_NormalizesImagePlatformBeforeScan(t *testing.T) {
	scanInfo := cautils.ScanInfo{ImagePlatform: "aarch64"}
	mock := &recordingKubescape{}
	cmd := getWorkloadCmd(mock, &scanInfo)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"Deployment/nginx"})

	require.NoError(t, cmd.Execute())
	require.NotNil(t, mock.captured)
	assert.Equal(t, "linux/arm64", mock.captured.ImagePlatform)
}

func TestGetWorkloadCmd_RejectsLabelSelector(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}
	cmd := getWorkloadCmd(mockKubescape, &scanInfo)

	scanInfo.LabelSelector = "app=nginx"

	cmd.SetArgs([]string{"Deployment/my-deploy"})
	err := cmd.RunE(cmd, []string{"Deployment/my-deploy"})

	assert.ErrorContains(t, err, "--label-selector is not supported for workload scans")
}

type scoredWorkloadKubescape struct {
	mocks.MockIKubescape
	complianceScore float32
}

func (m *scoredWorkloadKubescape) Scan(scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	rh := resultshandling.NewResultsHandler(nil, []printer.IPrinter{&fakePrinter{}}, &fakePrinter{})
	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.Report.SummaryDetails.ComplianceScore = m.complianceScore
	rh.SetData(sessionObj)
	return rh, nil
}

func (m *scoredWorkloadKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return m.Scan(scanInfo, policyIdentifiers)
}

func TestGetWorkloadCmd_EnforcesComplianceThreshold(t *testing.T) {
	tests := []struct {
		name            string
		complianceScore float32
		threshold       float32
		wantErr         string
	}{
		{
			name:            "score below threshold returns error",
			complianceScore: 50.0,
			threshold:       80.0,
			wantErr:         "scan compliance-score is below permitted threshold: 50.00 (compliance-threshold: 80.00)",
		},
		{
			name:            "score equal to threshold passes",
			complianceScore: 80.0,
			threshold:       80.0,
			wantErr:         "",
		},
		{
			name:            "score above threshold passes",
			complianceScore: 90.0,
			threshold:       80.0,
			wantErr:         "",
		},
		{
			name:            "zero threshold disables enforcement",
			complianceScore: 30.0,
			threshold:       0,
			wantErr:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := cautils.ScanInfo{ComplianceThreshold: tt.threshold}
			mock := &scoredWorkloadKubescape{complianceScore: tt.complianceScore}
			cmd := getWorkloadCmd(mock, &scanInfo)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"Deployment/nginx"})

			err := cmd.Execute()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
