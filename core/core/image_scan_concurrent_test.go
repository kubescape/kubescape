package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockImageScanService struct {
	mu           sync.Mutex
	scanCalls    int
	delay        time.Duration
	errByImage   map[string]error
	dataByImage  map[string]*cautils.ImageScanData
	invokedC     chan string
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

func TestRegistryThrottler(t *testing.T) {
	throttler := NewRegistryThrottler(2, 50*time.Millisecond)
	ctx := context.Background()

	assert.Equal(t, "docker.io", throttler.getRegistryDomain("nginx:latest"))
	assert.Equal(t, "gcr.io", throttler.getRegistryDomain("gcr.io/google-containers/pause:3.2"))
	assert.Equal(t, "quay.io", throttler.getRegistryDomain("quay.io/coreos/etcd:v3"))

	start := time.Now()
	require.NoError(t, throttler.Acquire(ctx, "nginx:latest"))
	require.NoError(t, throttler.Acquire(ctx, "gcr.io/ubuntu:22.04"))
	throttler.Release("nginx:latest")
	throttler.Release("gcr.io/ubuntu:22.04")

	elapsed := time.Since(start)
	assert.Less(t, elapsed, 40*time.Millisecond, "Parallel acquisitions across distinct registries should not trigger rate pacing")

	require.NoError(t, throttler.Acquire(ctx, "debian:latest"))
	throttler.Release("debian:latest")
	elapsed = time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond, "Subsequent acquisition on docker.io should respect minInterval pacing")
}

func TestLayerDeduplication(t *testing.T) {
	dedup := NewLayerDeduplicator()
	mockSvc := newMockImageScanService(0)
	mockSvc.dataByImage["docker.io/library/node:18-alpine"] = &cautils.ImageScanData{
		Image:    "docker.io/library/node:18-alpine",
		Packages: []pkg.Package{{Name: "musl", Version: "1.2.3"}},
		Matches:  match.NewMatches(),
	}

	layerGetter := func(ctx context.Context, image string, creds imagescan.RegistryCredentials) ([]string, error) {
		if strings.Contains(image, "alpine") {
			return []string{"sha256:alpine-base-layer"}, nil
		}
		return []string{"sha256:other-layer-" + image}, nil
	}

	dedupSvc := NewDeduplicatingImageScanService(mockSvc, dedup, nil, layerGetter)
	ctx := context.Background()

	res1, err := dedupSvc.Scan(ctx, "docker.io/library/node:18-alpine", imagescan.RegistryCredentials{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res1.Packages))
	assert.Equal(t, 1, mockSvc.scanCalls)

	hits, misses, cached := dedup.Stats()
	assert.Equal(t, uint64(0), hits)
	assert.Equal(t, uint64(1), misses)
	assert.Equal(t, 1, cached)

	res2, err := dedupSvc.Scan(ctx, "docker.io/library/python:3.10-alpine", imagescan.RegistryCredentials{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res2.Packages))
	assert.Equal(t, "musl", res2.Packages[0].Name)
	assert.Equal(t, 1, mockSvc.scanCalls, "Second alpine-based image should be served from layer dedup cache without calling mockSvc")

	hits, misses, _ = dedup.Stats()
	assert.Equal(t, uint64(1), hits)
	assert.Equal(t, uint64(1), misses)
}

func TestImageScanOrchestrator_Concurrency(t *testing.T) {
	mockSvc := newMockImageScanService(100 * time.Millisecond)
	orchestrator := NewImageScanOrchestrator(mockSvc, 4)
	ctx := context.Background()

	var jobs []ImageScanJob
	for i := 1; i <= 8; i++ {
		jobs = append(jobs, ImageScanJob{
			Image: fmt.Sprintf("docker.io/test/image:%d", i),
		})
	}

	start := time.Now()
	results := orchestrator.ScanImages(ctx, jobs)
	duration := time.Since(start)

	assert.Equal(t, 8, len(results))
	assert.Equal(t, 8, mockSvc.scanCalls)
	assert.Less(t, duration, 450*time.Millisecond, "Scanning 8 items with 100ms delay at concurrency 4 should finish around 200-300ms")
}

func TestConcurrentDeduplicatedImageScan_Suite(t *testing.T) {
	mockSvc := newMockImageScanService(50 * time.Millisecond)
	dedup := NewLayerDeduplicator()

	layerGetter := func(ctx context.Context, image string, creds imagescan.RegistryCredentials) ([]string, error) {
		if strings.Contains(image, "-base") {
			return []string{"sha256:shared-base-layer"}, nil
		}
		return []string{fmt.Sprintf("sha256:unique-%s", image)}, nil
	}

	dedupSvc := NewDeduplicatingImageScanService(mockSvc, dedup, nil, layerGetter)
	orchestrator := NewImageScanOrchestrator(dedupSvc, 5)
	ctx := context.Background()

	var jobs []ImageScanJob
	for i := 1; i <= 25; i++ {
		jobs = append(jobs, ImageScanJob{
			Image: fmt.Sprintf("docker.io/library/app-%d:latest-base", i),
		})
	}

	start := time.Now()
	results := orchestrator.ScanImages(ctx, jobs)
	duration := time.Since(start)

	assert.Equal(t, 25, len(results))
	for _, r := range results {
		assert.NoError(t, r.Error)
		assert.NotNil(t, r.ScanData)
	}

	hits, _, _ := dedup.Stats()
	assert.Greater(t, hits, uint64(15), "Bulk scan of 25 shared-base images should generate many layer deduplication hits")
	assert.Less(t, mockSvc.scanCalls, 25, "Under deduplication, fewer than 25 underlying scans should have taken place")
	t.Logf("Scan 25 shared base images completed in %v with %d actual scans and %d dedup hits", duration, mockSvc.scanCalls, hits)
}

func BenchmarkImageScan_ConcurrentVsSequential(b *testing.B) {
	images := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		images = append(images, fmt.Sprintf("gcr.io/demo/microservice-%d:v1-alpine", i))
	}

	layerGetter := func(ctx context.Context, image string, creds imagescan.RegistryCredentials) ([]string, error) {
		return []string{"sha256:alpine-common-base-layer-7890"}, nil
	}

	b.Run("Sequential_NoDedup", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			mockSvc := newMockImageScanService(10 * time.Millisecond)
			ctx := context.Background()
			for _, img := range images {
				_, _ = mockSvc.Scan(ctx, img, imagescan.RegistryCredentials{}, nil, nil)
			}
		}
	})

	b.Run("Concurrent_WithDedup", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			mockSvc := newMockImageScanService(10 * time.Millisecond)
			dedup := NewLayerDeduplicator()
			dedupSvc := NewDeduplicatingImageScanService(mockSvc, dedup, nil, layerGetter)
			orchestrator := NewImageScanOrchestrator(dedupSvc, 5)
			ctx := context.Background()

			var jobs []ImageScanJob
			for _, img := range images {
				jobs = append(jobs, ImageScanJob{Image: img})
			}
			_ = orchestrator.ScanImages(ctx, jobs)
		}
	})
}
