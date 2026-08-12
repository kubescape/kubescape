package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/stretchr/testify/assert"
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
