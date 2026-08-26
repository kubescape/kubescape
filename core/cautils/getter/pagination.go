package getter

import (
	"context"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ListFunc performs a single paginated request and returns the continuation token or an error.
type ListFunc func(metav1.ListOptions) (string, error)

// ListWithPagination executes a Kubernetes API list operation with chunked pagination,
// exponential backoff for rate limits, and context cancellation.
func ListWithPagination(ctx context.Context, listFunc ListFunc) error {
	limit := int64(100)
	continueToken := ""

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		listOptions := metav1.ListOptions{Limit: limit, Continue: continueToken}
		var nextToken string
		var err error

		retries := 5
		backoff := 1 * time.Second
		for i := 0; i < retries; i++ {
			nextToken, err = listFunc(listOptions)
			if err != nil {
				if k8serrors.IsTooManyRequests(err) {
					logger.L().Warning("Rate limited (429) when listing resources, retrying",
						helpers.Int("retry", i+1))

					if i == retries-1 {
						break
					}

					delay, ok := k8serrors.SuggestsClientDelay(err)
					currentBackoff := backoff
					if ok && delay > 0 {
						currentBackoff = time.Duration(delay) * time.Second
					}

					timer := time.NewTimer(currentBackoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
						if !ok || delay <= 0 {
							backoff *= 2
						}
						continue
					}
				}
				break
			}
			break
		}

		if err != nil {
			return err
		}

		if nextToken == "" {
			break
		}
		continueToken = nextToken
	}
	return nil
}
