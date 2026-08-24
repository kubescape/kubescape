package imagescan

import (
	"context"
	"errors"
	"math"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// parseRetryAfter parses the Retry-After header.
func parseRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		return 0
	}
	// Try parsing as seconds
	if s, err := strconv.Atoi(ra); err == nil {
		return time.Duration(s) * time.Second
	}
	// Try parsing as HTTP date
	if d, err := time.Parse(time.RFC1123, ra); err == nil {
		return time.Until(d)
	}
	return 0
}

// isRateLimitError checks if the given error is a rate limit (HTTP 429) error, returning a boolean and an optional Retry-After duration.
func isRateLimitError(err error) (bool, time.Duration) {
	if err == nil {
		return false, 0
	}

	// Check for gRPC ResourceExhausted
	if st, ok := status.FromError(err); ok {
		if st.Code() == codes.ResourceExhausted {
			return true, 0
		}
	}

	// Check for Azure azcore.ResponseError rate limiting
	var azErr *azcore.ResponseError
	if errors.As(err, &azErr) {
		if azErr.StatusCode == http.StatusTooManyRequests {
			return true, parseRetryAfter(azErr.RawResponse)
		}
	}

	errStr := strings.ToLower(err.Error())
	isRL := strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate exceeded") ||
		strings.Contains(errStr, "throttlingexception")
	return isRL, 0
}

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
// It implements concurrent processing with a static rate limiting token bucket and exponential backoff mechanism.
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

	var cooldownsMutex sync.Mutex
	cooldowns := make(map[string]time.Time)

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

					registry := j.imageID.Registry
					var waitTime time.Duration
					if registry != "" {
						cooldownsMutex.Lock()
						if deadline, ok := cooldowns[registry]; ok {
							if now := time.Now(); now.Before(deadline) {
								waitTime = time.Until(deadline)
							}
						}
						cooldownsMutex.Unlock()
						if waitTime > 0 {
							time.Sleep(waitTime)
						}
					}

					res, err = processFunc(j.imageID)
					if err == nil {
						break
					}

					isRL, retryAfter := isRateLimitError(err)
					if isRL && attempt < maxRetries {
						var backoff time.Duration
						if retryAfter > 0 {
							backoff = retryAfter
						} else {
							backoff = time.Duration(math.Pow(2, float64(attempt))) * baseDelay
						}
						logger.L().Warning("rate limit hit, backing off", helpers.Int("attempt", attempt+1), helpers.String("backoff", backoff.String()))
						
						if registry != "" {
							newDeadline := time.Now().Add(backoff)
							cooldownsMutex.Lock()
							if current, ok := cooldowns[registry]; !ok || current.Before(newDeadline) {
								cooldowns[registry] = newDeadline
							}
							cooldownsMutex.Unlock()
						}

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
