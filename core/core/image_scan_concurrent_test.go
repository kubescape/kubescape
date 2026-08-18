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
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
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
}

func newMockImageScanService(delay time.Duration) *mockImageScanService {
	return &mockImageScanService{
		delay:       delay,
		errByImage:  make(map[string]error),
		dataByImage: make(map[string]*cautils.ImageScanData),
		invokedC:    make(chan string, 100),
	}
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
	)
	require.Len(t, discoveryErrors, 1)
	assert.Contains(t, discoveryErrors[0].Error(), "kind: Pod")
	assert.Contains(t, discoveryErrors[0].Error(), "name: malformed")
	assert.Contains(t, discoveryErrors[0].Error(), "namespace: image-scan-test")

	jobs := make([]ImageScanJob, 0, images.Cardinality())
	for image := range images.Iter() {
		jobs = append(jobs, ImageScanJob{Image: image})
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
