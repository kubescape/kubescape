package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/version"
)

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
