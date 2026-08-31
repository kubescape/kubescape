package core

import (
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildImageScanJobsCarriesScanSettingsToEveryImage(t *testing.T) {
	imgScanInfo := &ksmetav1.ImageScanInfo{
		Images:    []string{"nginx:1.27", "redis:7"},
		Platform:  "linux/arm64",
		Authority: "registry.example.com",
		Username:  "user",
		Password:  "pass",
	}
	scanInfo := &cautils.ScanInfo{RegistryMapping: map[string]string{"docker.io": "mirror.example.com"}}

	jobs := buildImageScanJobs(imgScanInfo, scanInfo, nil)

	require.Len(t, jobs, 2)
	assert.Equal(t, "nginx:1.27", jobs[0].Image)
	assert.Equal(t, "redis:7", jobs[1].Image)
	for _, job := range jobs {
		assert.Equal(t, "linux/arm64", job.Platform)
		assert.Equal(t, scanInfo.RegistryMapping, job.RegistryMapping)
		require.Equal(t, []imagescan.RegistryCredentials{{
			Authority: "registry.example.com",
			Username:  "user",
			Password:  "pass",
		}}, job.RegistryCredentials)
	}
}

func TestBuildImageScanJobsResolvesExceptionsPerImage(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "nginx-only"},
			Targets:         []Target{{Attributes: Attributes{ImageName: "nginx"}}},
			Vulnerabilities: []string{"CVE-2024-0001"},
			Severities:      []string{"Low"},
		},
	}
	imgScanInfo := &ksmetav1.ImageScanInfo{Images: []string{"nginx:1.27", "redis:7"}}

	jobs := buildImageScanJobs(imgScanInfo, &cautils.ScanInfo{}, policies)

	require.Len(t, jobs, 2)
	assert.Contains(t, jobs[0].VulnerabilityExceptions, "CVE-2024-0001")
	assert.Equal(t, []string{"LOW"}, jobs[0].SeverityExceptions)
	assert.Empty(t, jobs[1].VulnerabilityExceptions, "an exception targeting nginx must not reach redis")
	assert.Empty(t, jobs[1].SeverityExceptions)
}

func TestImageScanWorkersFallsBackToDefault(t *testing.T) {
	assert.Equal(t, defaultImageScanConcurrency, imageScanWorkers(0))
	assert.Equal(t, defaultImageScanConcurrency, imageScanWorkers(-3))
	assert.Equal(t, 1, imageScanWorkers(1))
	assert.Equal(t, 8, imageScanWorkers(8))
}

func TestImageScanProgressMessages(t *testing.T) {
	single := []string{"nginx:1.27"}
	many := []string{"nginx:1.27", "redis:7", "postgres:16"}

	assert.Equal(t, "Scanning image nginx:1.27...", imageScanStartMessage(single))
	assert.Equal(t, "Scanning 3 images...", imageScanStartMessage(many))

	assert.Equal(t, "Successfully scanned image: nginx:1.27", imageScanSuccessMessage(single, make([]cautils.ImageScanData, 1)))
	assert.Equal(t, "Successfully scanned 3 images", imageScanSuccessMessage(many, make([]cautils.ImageScanData, 3)))
	assert.Equal(t, "Successfully scanned 2 of 3 images", imageScanSuccessMessage(many, make([]cautils.ImageScanData, 2)))

	assert.Equal(t, "Failed to scan image nginx:1.27", imageScanFailureMessage(single))
	assert.Equal(t, "Failed to scan 3 images", imageScanFailureMessage(many))
}

// An archive reference is not a parseable registry reference, so resolving
// exceptions against one logs a spurious attribute failure. It must not run
// when no exception policies are configured.
func TestBuildImageScanJobsSkipsExceptionResolutionWithoutPolicies(t *testing.T) {
	imgScanInfo := &ksmetav1.ImageScanInfo{Images: []string{"docker-archive:/tmp/image.tar"}}

	jobs := buildImageScanJobs(imgScanInfo, &cautils.ScanInfo{}, nil)

	require.Len(t, jobs, 1)
	assert.Nil(t, jobs[0].VulnerabilityExceptions)
	assert.Nil(t, jobs[0].SeverityExceptions)
}

func TestUnwrapSingleImageErrorReportsTheCauseDirectly(t *testing.T) {
	cause := errors.New("unauthorized: authentication required")
	aggregated := NewScanErrorAggregator()
	aggregated.Add("private.example/app:latest", cause)

	unwrapped := unwrapSingleImageError(aggregated)

	assert.EqualError(t, unwrapped, "failed to scan image private.example/app:latest: unauthorized: authentication required")
	assert.ErrorIs(t, unwrapped, cause)
}

func TestUnwrapSingleImageErrorKeepsAggregateForSeveralFailures(t *testing.T) {
	aggregated := NewScanErrorAggregator()
	aggregated.Add("first:latest", errors.New("boom"))
	aggregated.Add("second:latest", errors.New("bang"))

	assert.Same(t, aggregated, unwrapSingleImageError(aggregated))
	assert.Nil(t, unwrapSingleImageError(nil))
}
