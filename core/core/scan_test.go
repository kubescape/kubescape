package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/stretchr/testify/assert"
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
