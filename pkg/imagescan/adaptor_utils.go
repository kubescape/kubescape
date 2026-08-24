package imagescan

import (
	"context"
	"errors"
	"math"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/time/rate"
)

// isRateLimitError checks if the given error is a rate limit (HTTP 429) error.
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate exceeded") ||
		strings.Contains(errStr, "throttlingexception")
const maxRegistryAPIResponseBytes int64 = 64 << 20

func readRegistryAPIResponse(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxRegistryAPIResponseBytes
	}

	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read registry api response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("registry api response exceeds the %d-byte limit", limit)
	}
	return data, nil
}

// FetchImagesInformation provides a shared implementation for GetImagesInformation across adaptors.
func FetchImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	var infos []ContainerImageInformation
	for _, imageID := range imageIDs {
		infos = append(infos, ContainerImageInformation{
			ImageID: imageID,
			Bom:     []string{},
		})
	}
	return infos, nil
}

// NormalizeSeverity converts common provider severity strings to Kubescape standard.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "minimal", "informational", "untriaged", "unassigned", "negligible", "none":
		return "Negligible"
	default:
		return "Unknown"
	}
}

// ProcessImages iterates over imageIDs and calls the provided fetch function, handling errors and aggregating results.
// It implements concurrent processing with an adaptive rate limiting token bucket and exponential backoff mechanism.
func ProcessImages[T any](
	imageIDs []ContainerImageIdentifier,
	processFunc func(imageID ContainerImageIdentifier) (T, error),
) ([]T, error) {
	var aggErr error
	var aggErrMutex sync.Mutex

	if len(imageIDs) == 0 {
		return []T{}, nil
	}

	results := make([]T, len(imageIDs))

	// Create a centralized rate limiter: 5 requests per second, burst of 10
	limiter := rate.NewLimiter(rate.Limit(5), 10)
	ctx := context.Background()

	// Use a worker pool pattern
	numWorkers := 5
	if numWorkers > len(imageIDs) {
		numWorkers = len(imageIDs)
	}

	type job struct {
		index   int
		imageID ContainerImageIdentifier
	}

	jobs := make(chan job, len(imageIDs))
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				var res T
				var err error

				maxRetries := 5
				baseDelay := time.Second

				for attempt := 0; attempt <= maxRetries; attempt++ {
					// Wait based on global rate limit before firing the request
					_ = limiter.Wait(ctx)

					res, err = processFunc(j.imageID)
					if err == nil {
						break
					}

					if isRateLimitError(err) && attempt < maxRetries {
						backoff := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
						logger.L().Warning("rate limit hit, backing off", helpers.Int("attempt", attempt+1), helpers.String("backoff", backoff.String()))
						time.Sleep(backoff)
						continue
					}

					break
				}

				if err != nil {
					logger.L().Warning("skipping image due to api error", helpers.Error(err))
					aggErrMutex.Lock()
					aggErr = errors.Join(aggErr, err)
					aggErrMutex.Unlock()
				}

				results[j.index] = res
			}
		}()
	}

	for i, imageID := range imageIDs {
		jobs <- job{index: i, imageID: imageID}
	}
	close(jobs)
	wg.Wait()

	return results, aggErr
}
