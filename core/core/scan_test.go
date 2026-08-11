package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/version"
)

type recordingImageScanService struct {
	image              string
	credentials        imagescan.RegistryCredentials
	registryMappingErr error
}

func (s *recordingImageScanService) Scan(_ context.Context, image string, credentials imagescan.RegistryCredentials, _, _ []string) (*cautils.ImageScanData, error) {
	s.image = image
	s.credentials = credentials
	if s.registryMappingErr != nil {
		return nil, s.registryMappingErr
	}
	return &cautils.ImageScanData{Image: image}, nil
}

// estimateClusterSizeMock implements resourcehandler.IResourceHandler with a
// controllable EstimateClusterSize return value. All other methods are stubs.
type estimateClusterSizeMock struct {
	size int
	err  error
}

func (m estimateClusterSizeMock) GetResources(context.Context, *cautils.OPASessionObj, *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
	return nil, nil, nil, nil, nil
}

func (m estimateClusterSizeMock) StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error) {
	return nil, nil, 0, nil
}

func (m estimateClusterSizeMock) EstimateClusterSize(ctx context.Context, scanInfo *cautils.ScanInfo) (int, error) {
	return m.size, m.err
}

func (m estimateClusterSizeMock) GetClusterAPIServerInfo(ctx context.Context) *version.Info {
	return nil
}

func (m estimateClusterSizeMock) GetCloudProvider() string {
	return ""
}

func TestEstimateClusterSize(t *testing.T) {
	// A ScanInfo with no input patterns is treated as a cluster scan.
	clusterScanInfo := &cautils.ScanInfo{}

	// A ScanInfo with an explicit file input is treated as a file scan.
	fileScanInfo := &cautils.ScanInfo{
		InputPatterns: []string{"deployment.yaml"},
	}

	tests := []struct {
		name     string
		handler  resourcehandler.IResourceHandler
		scanInfo *cautils.ScanInfo
		want     int
	}{
		{
			name:     "non-cluster context returns 0",
			handler:  estimateClusterSizeMock{size: 5000},
			scanInfo: fileScanInfo,
			want:     0,
		},
		{
			name:     "handler error falls back to 0",
			handler:  estimateClusterSizeMock{err: errors.New("API unavailable")},
			scanInfo: clusterScanInfo,
			want:     0,
		},
		{
			name:     "small cluster estimate",
			handler:  estimateClusterSizeMock{size: 500},
			scanInfo: clusterScanInfo,
			want:     500,
		},
		{
			name:     "large cluster estimate",
			handler:  estimateClusterSizeMock{size: 10000},
			scanInfo: clusterScanInfo,
			want:     10000,
		},
		{
			name:     "zero estimate (empty cluster)",
			handler:  estimateClusterSizeMock{size: 0},
			scanInfo: clusterScanInfo,
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateClusterSize(tt.handler, context.Background(), tt.scanInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetOutputPrinters(t *testing.T) {
	ctx := context.Background()
	scanInfo := &cautils.ScanInfo{
		ScanType: "control",
		Format:   "json,junit,html",
	}

	outputPrinters, err := GetOutputPrinters(scanInfo, ctx, "test-cluster")

	assert.NoError(t, err)
	assert.NotNil(t, outputPrinters)
	assert.Equal(t, 3, len(outputPrinters))
}

func TestGetOutputPrintersCollisionReturnsError(t *testing.T) {
	scanInfo := &cautils.ScanInfo{
		ScanType: cautils.ScanTypeControl,
		Format:   "prometheus,pretty-printer",
		Output:   "report",
	}

	_, err := GetOutputPrinters(scanInfo, context.Background(), "test-cluster")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output path collision")
}

func TestResolvedOutputPath(t *testing.T) {
	tests := []struct {
		name, format, outputFile, want string
	}{
		{"append JSON", printer.JsonFormat, "report", "report.json"},
		{"preserve JSON", printer.JsonFormat, "report.json", "report.json"},
		{"preserve YAML alias", printer.YamlFormat, "report.yml", "report.yml"},
		{"preserve CycloneDX", printer.CycloneDXFormat, "report.cdx.json", "report.cdx.json"},
		{"append CycloneDX", printer.CycloneDXFormat, "report.json", "report.json.cdx.json"},
		{"preserve SPDX", printer.SPDXFormat, "report.spdx.json", "report.spdx.json"},
		{"append SPDX", printer.SPDXFormat, "report.json", "report.json.spdx.json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, resolvedOutputPath(test.format, test.outputFile))
		})
	}
}

func TestResolvedOutputPathExposesSBOMCollisions(t *testing.T) {
	tests := []struct {
		sbomFormat, outputFile string
	}{
		{printer.CycloneDXFormat, "report.cdx.json"},
		{printer.SPDXFormat, "report.spdx.json"},
	}

	for _, test := range tests {
		t.Run(test.sbomFormat, func(t *testing.T) {
			jsonPath := resolvedOutputPath(printer.JsonFormat, test.outputFile)
			sbomPath := resolvedOutputPath(test.sbomFormat, test.outputFile)
			assert.Equal(t, jsonPath, sbomPath)
		})
	}
}

func TestGetOutputPrintersRejectsSBOMMultipartExtensionCollisions(t *testing.T) {
	tests := []struct {
		format, outputFile string
	}{
		{"json,cyclonedx-json", "report.cdx.json"},
		{"json,spdx-json", "report.spdx.json"},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				ScanType: cautils.ScanTypeImage,
				Format:   test.format,
				Output:   filepath.Join(t.TempDir(), test.outputFile),
			}

			_, err := GetOutputPrinters(scanInfo, context.Background(), "")
			require.ErrorContains(t, err, "output path collision")
		})
	}
}

func TestIsPrioritizationScanType(t *testing.T) {
	tests := []struct {
		name cautils.ScanTypes
		want bool
	}{
		{
			name: cautils.ScanTypeCluster,
			want: true,
		},
		{
			name: cautils.ScanTypeRepo,
			want: true,
		},
		{
			name: cautils.ScanTypeImage,
			want: false,
		},
		{
			name: cautils.ScanTypeWorkload,
			want: false,
		},
		{
			name: cautils.ScanTypeFramework,
			want: false,
		},
		{
			name: cautils.ScanTypeControl,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.name), func(t *testing.T) {
			assert.Equal(t, tt.want, isPrioritizationScanType(tt.name))
		})
	}
}

func TestRegistryCredentialsFromScanInfo(t *testing.T) {
	scanInfo := &cautils.ScanInfo{
		RegistryAuthority: "registry.example.com",
		RegistryUsername:  "user",
		RegistryPassword:  "pass",
		RegistryToken:     "token",
	}

	creds := registryCredentialsFromScanInfo(scanInfo)

	assert.Equal(t, imagescan.RegistryCredentials{
		Authority: "registry.example.com",
		Username:  "user",
		Password:  "pass",
		Token:     "token",
	}, creds)
	assert.Equal(t, imagescan.RegistryCredentials{}, registryCredentialsFromScanInfo(nil))
}

func TestScanSingleImageForwardsRegistryCredentials(t *testing.T) {
	svc := &recordingImageScanService{}
	results := &resultshandling.ResultsHandler{}
	creds := imagescan.RegistryCredentials{
		Authority: "registry.example.com",
		Username:  "user",
		Password:  "pass",
	}

	err := scanSingleImage(context.Background(), "registry.example.com/app:tag", svc, results, nil, creds)

	assert.NoError(t, err)
	assert.Equal(t, "registry.example.com/app:tag", svc.image)
	assert.Equal(t, creds, svc.credentials)
	assert.Len(t, results.ImageScanData, 1)
	assert.Equal(t, "registry.example.com/app:tag", results.ImageScanData[0].Image)
}

func TestScanSingleImageReturnsScannerError(t *testing.T) {
	expectedErr := errors.New("scan failed")
	svc := &recordingImageScanService{registryMappingErr: expectedErr}
	results := &resultshandling.ResultsHandler{}

	err := scanSingleImage(context.Background(), "registry.example.com/app:tag", svc, results, nil, imagescan.RegistryCredentials{})

	assert.ErrorIs(t, err, expectedErr)
	assert.Empty(t, results.ImageScanData)
}

func TestIsAirGappedMode(t *testing.T) {
	tests := []struct {
		name     string
		scanInfo *cautils.ScanInfo
		want     bool
	}{
		{
			name: "not air-gapped with Local flag",
			scanInfo: &cautils.ScanInfo{
				Local: true,
			},
			want: false,
		},
		{
			name: "air-gapped with UseFrom",
			scanInfo: &cautils.ScanInfo{
				UseFrom: []string{"/path/to/policy"},
			},
			want: true,
		},
		{
			name: "not air-gapped with ControlsInputs",
			scanInfo: &cautils.ScanInfo{
				ControlsInputs: "/path/to/controls",
			},
			want: false,
		},
		{
			name: "not air-gapped with UseExceptions",
			scanInfo: &cautils.ScanInfo{
				UseExceptions: "/path/to/exceptions",
			},
			want: false,
		},
		{
			name: "not air-gapped with AttackTracks",
			scanInfo: &cautils.ScanInfo{
				AttackTracks: "/path/to/attack-tracks",
			},
			want: false,
		},
		{
			name:     "not air-gapped - all empty",
			scanInfo: &cautils.ScanInfo{},
			want:     false,
		},
		{
			name: "air-gapped with multiple flags",
			scanInfo: &cautils.ScanInfo{
				Local:   true,
				UseFrom: []string{"/path/to/policy"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAirGappedMode(tt.scanInfo))
		})
	}
}

func TestGetOutputPrintersDeduplicatesPrettyPrinterFallback(t *testing.T) {
	tests := []struct {
		name        string
		scanType    cautils.ScanTypes
		format      string
		expectedLen int
	}{
		{
			name:        "cluster scan: pretty-printer and invalid format should create single pretty-printer",
			scanType:    cautils.ScanTypeCluster,
			format:      "pretty-printer,abc",
			expectedLen: 1,
		},
		{
			name:        "cluster scan: multiple invalid formats should create single pretty-printer",
			scanType:    cautils.ScanTypeCluster,
			format:      "abc,def,ghi",
			expectedLen: 1,
		},

		{
			name:        "repo scan: pretty-printer and invalid format should create single pretty-printer",
			scanType:    cautils.ScanTypeRepo,
			format:      "pretty-printer,abc",
			expectedLen: 1,
		},
		{
			name:        "repo scan: multiple invalid formats should create single pretty-printer",
			scanType:    cautils.ScanTypeRepo,
			format:      "abc,def,ghi",
			expectedLen: 1,
		},

		{
			name:        "framework scan: pretty-printer and invalid format should create single pretty-printer",
			scanType:    cautils.ScanTypeFramework,
			format:      "pretty-printer,abc",
			expectedLen: 1,
		},
		{
			name:        "framework scan: multiple invalid formats should create single pretty-printer",
			scanType:    cautils.ScanTypeFramework,
			format:      "abc,def,ghi",
			expectedLen: 1,
		},

		{
			name:        "control scan: pretty-printer and invalid format should create single pretty-printer",
			scanType:    cautils.ScanTypeControl,
			format:      "pretty-printer,abc",
			expectedLen: 1,
		},
		{
			name:        "control scan: multiple invalid formats should create single pretty-printer",
			scanType:    cautils.ScanTypeControl,
			format:      "abc,def,ghi",
			expectedLen: 1,
		},

		{
			name:        "workload scan: pretty-printer and invalid format should create single pretty-printer",
			scanType:    cautils.ScanTypeWorkload,
			format:      "pretty-printer,abc",
			expectedLen: 1,
		},
		{
			name:        "workload scan: multiple invalid formats should create single pretty-printer",
			scanType:    cautils.ScanTypeWorkload,
			format:      "abc,def,ghi",
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				Format:   tt.format,
				ScanType: tt.scanType,
			}

			got, err := GetOutputPrinters(scanInfo, context.Background(), "test-cluster")

			assert.NoError(t, err)
			assert.Len(t, got, tt.expectedLen)
		})
	}
}

func TestKubescape_SetContext(t *testing.T) {
	type ctxKey struct{}
	ks := NewKubescape(context.Background())

	newCtx := context.WithValue(context.Background(), ctxKey{}, "sentinel")
	ks.SetContext(newCtx)

	assert.Equal(t, newCtx, ks.Context())
	assert.Equal(t, "sentinel", ks.Context().Value(ctxKey{}))
}

func TestKubescape_SetContextRestoresOriginal(t *testing.T) {
	originalCtx := context.Background()
	ks := NewKubescape(originalCtx)

	timeoutCtx, cancel := context.WithTimeout(originalCtx, time.Minute)
	ks.SetContext(timeoutCtx)
	_, hasDeadline := ks.Context().Deadline()
	assert.True(t, hasDeadline)

	cancel()
	ks.SetContext(originalCtx)
	_, hasDeadline = ks.Context().Deadline()
	assert.False(t, hasDeadline)
}

type streamingCancelMock struct {
	estimateClusterSizeMock
	passedCtx                     context.Context
	apiServerInfo                 *version.Info
	cloudProvider                 string
	providerAtStreamingSetup      string
	apiServerInfoAtStreamingSetup *version.Info
	scanningScopeAtStreamingSetup reporthandling.ScanningScopeType
}

func (m *streamingCancelMock) StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error) {
	m.passedCtx = ctx
	m.providerAtStreamingSetup = sessionObj.Report.ClusterCloudProvider
	m.apiServerInfoAtStreamingSetup = sessionObj.Report.ClusterAPIServerInfo
	m.scanningScopeAtStreamingSetup = cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)
	batchChan := make(chan *cautils.ResourceBatch, 1)
	errChan := make(chan error, 1)
	batchChan <- cautils.NewResourceBatch(cautils.ClusterScope)
	close(batchChan)
	close(errChan)
	return batchChan, errChan, 0, nil
}

func (m *streamingCancelMock) GetClusterAPIServerInfo(context.Context) *version.Info {
	return m.apiServerInfo
}

func (m *streamingCancelMock) GetCloudProvider() string {
	return m.cloudProvider
}

func TestCollectAndProcessResourcesWithStreaming_InitializesProviderScope(t *testing.T) {
	apiServerInfo := &version.Info{GitVersion: "v1.31.0-eks"}
	mockHandler := &streamingCancelMock{
		apiServerInfo: apiServerInfo,
		cloudProvider: "eks",
	}
	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
		ContextName: "arn:aws:eks:us-east-1:123456789012:cluster/production",
	}

	err := collectAndProcessResourcesWithStreaming(context.Background(), mockHandler, sessionObj, &cautils.ScanInfo{}, "cluster", "", "", false, time.Second, 3000)

	require.NoError(t, err)
	assert.Same(t, apiServerInfo, sessionObj.Report.ClusterAPIServerInfo)
	assert.Equal(t, "EKS", sessionObj.Report.ClusterCloudProvider)
	require.NotNil(t, sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudMetadata)
	assert.Equal(t, "EKS", mockHandler.providerAtStreamingSetup,
		"cloud provider must be available before streaming starts")
	assert.Same(t, apiServerInfo, mockHandler.apiServerInfoAtStreamingSetup,
		"API server info must be available before streaming starts")
	assert.Equal(t, reporthandling.ScopeCloudEKS, mockHandler.scanningScopeAtStreamingSetup,
		"provider-scoped frameworks must not be filtered from streaming scans")
}

func TestCollectAndProcessResourcesWithStreaming_CancelsProducerContext(t *testing.T) {
	mockHandler := &streamingCancelMock{}
	sessionObj := cautils.NewOPASessionObjMock()
	scanInfo := &cautils.ScanInfo{}

	parentCtx := context.Background()

	_ = collectAndProcessResourcesWithStreaming(parentCtx, mockHandler, sessionObj, scanInfo, "cluster", "", "", false, time.Second, 10)

	require.NotNil(t, mockHandler.passedCtx)
	assert.NoError(t, parentCtx.Err(), "parent context must remain uncanceled")
	assert.Equal(t, context.Canceled, mockHandler.passedCtx.Err(), "derived producer context must be canceled when function returns")
}

func TestGetAllWorkloadImages(t *testing.T) {
	podData := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "main-app",
					"image": "app:v1",
				},
			},
			"initContainers": []interface{}{
				map[string]interface{}{
					"name":  "init-setup",
					"image": "init:v1",
				},
			},
			"ephemeralContainers": []interface{}{
				map[string]interface{}{
					"name":  "debug-tool",
					"image": "debug:v1",
				},
			},
		},
	}

	wl := workloadinterface.NewWorkloadObj(podData)
	images := getAllWorkloadImages(wl)

	assert.Contains(t, images, "app:v1")
	assert.Contains(t, images, "init:v1")
	assert.Contains(t, images, "debug:v1")
	assert.Len(t, images, 3)
}
