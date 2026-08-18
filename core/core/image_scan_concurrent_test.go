package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockImageScanService struct {
	mu          sync.Mutex
	scanCalls   int
	delay       time.Duration
	errByImage  map[string]error
	dataByImage map[string]*cautils.ImageScanData
	invokedC    chan string
	inFlight    int
	maxInFlight int
	platforms   map[string][]string
}

func newMockImageScanService(delay time.Duration) *mockImageScanService {
	return &mockImageScanService{
		delay:       delay,
		errByImage:  make(map[string]error),
		dataByImage: make(map[string]*cautils.ImageScanData),
		invokedC:    make(chan string, 100),
		platforms:   make(map[string][]string),
	}
}

func (m *mockImageScanService) ScanWithOptions(ctx context.Context, img string, creds imagescan.RegistryCredentials, vulnExceptions, sevExceptions []string, options imagescan.ScanOptions) (*cautils.ImageScanData, error) {
	m.mu.Lock()
	m.platforms[img] = append(m.platforms[img], options.Platform)
	m.mu.Unlock()

	data, err := m.Scan(ctx, img, creds, vulnExceptions, sevExceptions)
	if data == nil || err != nil {
		return data, err
	}
	copy := *data
	copy.Platform = options.Platform
	return &copy, nil
}

func (m *mockImageScanService) Scan(ctx context.Context, img string, creds imagescan.RegistryCredentials, vulnExceptions, sevExceptions []string) (*cautils.ImageScanData, error) {
	m.mu.Lock()
	m.inFlight++
	if m.inFlight > m.maxInFlight {
		m.maxInFlight = m.inFlight
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.inFlight--
		m.mu.Unlock()
	}()

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	m.mu.Lock()
	m.scanCalls++
	err, hasErr := m.errByImage[img]
	data, hasData := m.dataByImage[img]
	m.mu.Unlock()

	select {
	case m.invokedC <- img:
	default:
	}

	if hasErr {
		return nil, err
	}
	if hasData {
		return data, nil
	}

	return &cautils.ImageScanData{
		Image: img,
	}, nil
}

func TestCategorizationOfScanErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ScanErrorCategory
	}{
		{
			name:     "Nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "DNS Timeout error",
			err:      &net.DNSError{Err: "no such host", Name: "registry.example.com"},
			expected: ErrCategoryDNSTimeout,
		},
		{
			name:     "Credentials error",
			err:      errors.New("unauthorized: authentication required"),
			expected: ErrCategoryCredentials,
		},
		{
			name:     "Parser error",
			err:      errors.New("failed to parse manifest: unknown format"),
			expected: ErrCategoryParser,
		},
		{
			name:     "General error",
			err:      errors.New("unexpected database disconnection"),
			expected: ErrCategoryGeneral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat := CategorizeScanError(tt.err)
			assert.Equal(t, tt.expected, cat)
		})
	}
}

func TestScanErrorAggregator(t *testing.T) {
	agg := NewScanErrorAggregator()
	assert.False(t, agg.HasErrors())
	assert.Equal(t, "", agg.Error())

	agg.Add("img-dns", &net.DNSError{Err: "no such host", Name: "bad.io"})
	agg.Add("img-auth", errors.New("401 unauthorized"))
	agg.Add("img-auth2", errors.New("forbidden login"))
	agg.Add("img-parse", errors.New("malformed manifest syntax"))

	assert.True(t, agg.HasErrors())
	summary := agg.Summary()
	assert.Equal(t, 1, summary[ErrCategoryDNSTimeout])
	assert.Equal(t, 2, summary[ErrCategoryCredentials])
	assert.Equal(t, 1, summary[ErrCategoryParser])

	errStr := agg.Error()
	assert.Contains(t, errStr, "Aggregated image scan errors:")
	assert.Contains(t, errStr, "Registry DNSTimeout/Unreachable")
	assert.Contains(t, errStr, "Registry Credentials/Authentication")
	assert.Contains(t, errStr, "Image Manifest/Parser Issue")
}

func TestImageScanOrchestrator_Concurrency(t *testing.T) {
	mockSvc := newMockImageScanService(10 * time.Millisecond)
	orchestrator := NewImageScanOrchestrator(mockSvc, 4)
	ctx := context.Background()

	var jobs []ImageScanJob
	for i := 1; i <= 8; i++ {
		jobs = append(jobs, ImageScanJob{
			Image: fmt.Sprintf("docker.io/test/image:%d", i),
		})
	}

	results := orchestrator.ScanImages(ctx, jobs)

	assert.Equal(t, 8, len(results))
	assert.Equal(t, 8, mockSvc.scanCalls)

	for _, r := range results {
		assert.NoError(t, r.Error)
		assert.NotNil(t, r.ScanData)
	}

	assert.LessOrEqual(t, mockSvc.maxInFlight, 4, "Maximum in-flight calls should not exceed configured concurrency of 4")
	assert.Greater(t, mockSvc.maxInFlight, 0, "Should have executed concurrently")
}

func TestImageScanOrchestratorForwardsTargetPlatform(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	orchestrator := NewImageScanOrchestrator(mockSvc, 2)

	results := orchestrator.ScanImages(context.Background(), []ImageScanJob{
		{Image: "example/app:latest", Platform: "linux/amd64"},
		{Image: "example/app:latest", Platform: "linux/arm64"},
	})

	require.Len(t, results, 2)
	actualPlatforms := make(map[string]bool)
	for _, result := range results {
		require.NoError(t, result.Error)
		require.NotNil(t, result.ScanData)
		assert.Equal(t, result.Platform, result.ScanData.Platform)
		assert.Equal(t, result.Image, result.ScanData.Image)
		actualPlatforms[result.Platform] = true
	}
	assert.Equal(t, map[string]bool{
		"linux/amd64": true,
		"linux/arm64": true,
	}, actualPlatforms)

	mockSvc.mu.Lock()
	defer mockSvc.mu.Unlock()
	assert.ElementsMatch(t, []string{"linux/amd64", "linux/arm64"}, mockSvc.platforms["example/app:latest"])
}

func TestImageScanOrchestratorIncludesPlatformInErrors(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	mockSvc.errByImage["example/app:latest"] = errors.New("manifest unavailable")
	orchestrator := NewImageScanOrchestrator(mockSvc, 1)

	results := orchestrator.ScanImages(context.Background(), []ImageScanJob{{
		Image: "example/app:latest", Platform: "linux/arm64",
	}})

	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	require.NotNil(t, orchestrator.GetErrorAggregator())
	assert.Contains(t, orchestrator.GetErrorAggregator().Error(), "example/app:latest [linux/arm64]")
}

type legacyImageScanService struct {
	calls int
}

func (s *legacyImageScanService) Scan(_ context.Context, image string, _ imagescan.RegistryCredentials, _, _ []string) (*cautils.ImageScanData, error) {
	s.calls++
	return &cautils.ImageScanData{Image: image}, nil
}

func TestScanImageForPlatformPreservesLegacyEmptyPlatform(t *testing.T) {
	svc := &legacyImageScanService{}

	data, err := scanImageForPlatform(context.Background(), svc, "example/app:latest", imagescan.RegistryCredentials{}, nil, nil, "")

	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Equal(t, "example/app:latest", data.Image)
	assert.Empty(t, data.Platform)
	assert.Equal(t, 1, svc.calls)
}

func TestScanImageForPlatformRejectsUnsupportedService(t *testing.T) {
	svc := &legacyImageScanService{}

	data, err := scanImageForPlatform(context.Background(), svc, "example/app:latest", imagescan.RegistryCredentials{}, nil, nil, "linux/arm64")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support target platform")
	assert.Nil(t, data)
	assert.Zero(t, svc.calls)
}

func TestScanWithRegistryMappingPreservesPlatformOnFallback(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	original := "internal.registry.svc/team/app:v2"
	mapped := "registry.example.com/team/app:v2"
	mockSvc.errByImage[original] = &net.DNSError{Err: "no such host", Name: "internal.registry.svc"}
	mockSvc.dataByImage[mapped] = &cautils.ImageScanData{Image: mapped}

	data, err := scanWithRegistryMapping(
		context.Background(),
		mockSvc,
		original,
		[]imagescan.RegistryCredentials{{}},
		map[string]string{"internal.registry.svc": "registry.example.com"},
		nil,
		nil,
		"linux/arm64",
	)

	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Equal(t, mapped, data.Image)
	assert.Equal(t, "linux/arm64", data.Platform)
	mockSvc.mu.Lock()
	defer mockSvc.mu.Unlock()
	assert.Equal(t, []string{"linux/arm64"}, mockSvc.platforms[original])
	assert.Equal(t, []string{"linux/arm64"}, mockSvc.platforms[mapped])
}

func TestScanWithRegistryMappingReportsPlatformCapabilityError(t *testing.T) {
	legacy := &legacyImageScanService{}

	data, err := scanWithRegistryMapping(
		context.Background(),
		legacy,
		"registry.example.com/team/app:v2",
		[]imagescan.RegistryCredentials{{}},
		nil,
		nil,
		nil,
		"linux/amd64",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `does not support target platform "linux/amd64"`)
	assert.Nil(t, data)
	assert.Zero(t, legacy.calls)
}

func TestScanImageJobsOrdersImageVariantsDeterministically(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	results := &resultshandling.ResultsHandler{}
	jobs := []ImageScanJob{
		{Image: "registry.example.com/zeta:v1", Platform: "linux/arm64"},
		{Image: "registry.example.com/app:v2", Platform: "windows/amd64"},
		{Image: "registry.example.com/app:v2", Platform: "linux/arm64"},
		{Image: "registry.example.com/app:v2", Platform: "linux/amd64"},
	}

	err := scanImageJobs(context.Background(), mockSvc, 4, jobs, results)

	require.NoError(t, err)
	require.Len(t, results.ImageScanData, 4)
	assert.Equal(t, []string{
		"registry.example.com/app:v2 [linux/amd64]",
		"registry.example.com/app:v2 [linux/arm64]",
		"registry.example.com/app:v2 [windows/amd64]",
		"registry.example.com/zeta:v1 [linux/arm64]",
	}, []string{
		results.ImageScanData[0].Target(),
		results.ImageScanData[1].Target(),
		results.ImageScanData[2].Target(),
		results.ImageScanData[3].Target(),
	})
}

func TestScanImageJobsScansEachVariantExactlyOnce(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	results := &resultshandling.ResultsHandler{}
	jobs := []ImageScanJob{
		{Image: "registry.example.com/app:v2", Platform: "linux/amd64"},
		{Image: "registry.example.com/app:v2", Platform: "linux/arm64"},
		{Image: "registry.example.com/app:v2", Platform: "windows/amd64"},
	}

	err := scanImageJobs(context.Background(), mockSvc, 2, jobs, results)

	require.NoError(t, err)
	assert.Equal(t, 3, mockSvc.scanCalls)
	require.Len(t, results.ImageScanData, 3)
	mockSvc.mu.Lock()
	defer mockSvc.mu.Unlock()
	assert.ElementsMatch(t,
		[]string{"linux/amd64", "linux/arm64", "windows/amd64"},
		mockSvc.platforms["registry.example.com/app:v2"],
	)
}

func TestImageScanTargetDoesNotChangeRegistryReference(t *testing.T) {
	tests := []struct {
		image    string
		platform string
		want     string
	}{
		{
			image: "nginx:latest",
			want:  "nginx:latest",
		},
		{
			image:    "registry.example.com:5000/team/app@sha256:0123456789abcdef",
			platform: "linux/amd64",
			want:     "registry.example.com:5000/team/app@sha256:0123456789abcdef [linux/amd64]",
		},
		{
			image:    "docker-archive:/tmp/image.tar",
			platform: "linux/arm64",
			want:     "docker-archive:/tmp/image.tar [linux/arm64]",
		},
		{
			image:    "oci-dir:/tmp/layout",
			platform: "windows/amd64",
			want:     "oci-dir:/tmp/layout [windows/amd64]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, imageScanTarget(tt.image, tt.platform))
		})
	}
}

func TestScanImageJobsReturnsErrorsAndPreservesPartialResults(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	scanErr := errors.New("unauthorized: authentication required")
	mockSvc.errByImage["private.example/fail:latest"] = scanErr
	mockSvc.dataByImage["example/success:latest"] = &cautils.ImageScanData{Image: "example/success:latest"}
	results := &resultshandling.ResultsHandler{}

	err := scanImageJobs(context.Background(), mockSvc, 2, []ImageScanJob{
		{Image: "private.example/fail:latest"},
		{Image: "example/success:latest"},
	}, results)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "private.example/fail:latest")
	assert.Contains(t, err.Error(), scanErr.Error())
	require.Len(t, results.ImageScanData, 1)
	assert.Equal(t, "example/success:latest", results.ImageScanData[0].Image)
}

func TestScanImageJobsReturnsCancellationError(t *testing.T) {
	mockSvc := newMockImageScanService(0)
	results := &resultshandling.ResultsHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := scanImageJobs(ctx, mockSvc, 1, []ImageScanJob{
		{Image: "example/canceled:latest"},
	}, results)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "example/canceled:latest")
	assert.Contains(t, err.Error(), context.Canceled.Error())
	assert.Zero(t, mockSvc.scanCalls)
	assert.Empty(t, results.ImageScanData)
}

func TestScanImageJobsReturnsDiscoveryAndWorkerErrorsWithPartialResults(t *testing.T) {
	newPod := func(name string, containers interface{}) *workloadinterface.Workload {
		return workloadinterface.NewWorkloadObj(map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "image-scan-test",
			},
			"spec": map[string]interface{}{
				"containers": containers,
			},
		})
	}

	malformed := newPod("malformed", "not-a-container-list")
	failing := newPod("worker-failure", []interface{}{
		map[string]interface{}{"name": "app", "image": "private.example/fail:latest"},
	})
	successful := newPod("worker-success", []interface{}{
		map[string]interface{}{"name": "app", "image": "example/success:latest"},
	})
	scanData := cautils.NewOPASessionObjMock()
	for _, workload := range []*workloadinterface.Workload{malformed, failing, successful} {
		scanData.AllResources[workload.GetID()] = workload
	}

	images, _, discoveryErrors := collectImageScanTargets(
		cautils.ScanTypeCluster,
		scanData,
		context.Background(),
		cautils.ContextFile,
		nil,
		"",
	)
	require.Len(t, discoveryErrors, 1)
	assert.Contains(t, discoveryErrors[0].Error(), "kind: Pod")
	assert.Contains(t, discoveryErrors[0].Error(), "name: malformed")
	assert.Contains(t, discoveryErrors[0].Error(), "namespace: image-scan-test")

	jobs := make([]ImageScanJob, 0, images.Cardinality())
	for image := range images.Iter() {
		jobs = append(jobs, ImageScanJob{Image: image.Image, Platform: image.Platform})
	}
	mockSvc := newMockImageScanService(0)
	workerErr := errors.New("unauthorized: authentication required")
	mockSvc.errByImage["private.example/fail:latest"] = workerErr
	mockSvc.dataByImage["example/success:latest"] = &cautils.ImageScanData{Image: "example/success:latest"}
	results := &resultshandling.ResultsHandler{}

	err := scanImageJobsWithDiscoveryErrors(context.Background(), mockSvc, 2, jobs, results, discoveryErrors)

	require.Error(t, err)
	assert.Contains(t, err.Error(), discoveryErrors[0].Error())
	assert.Contains(t, err.Error(), "private.example/fail:latest")
	assert.Contains(t, err.Error(), workerErr.Error())
	require.Len(t, results.ImageScanData, 1)
	assert.Equal(t, "example/success:latest", results.ImageScanData[0].Image)
}
