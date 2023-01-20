package hostsensorutils

import (
	"context"
	"fmt"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"golang.org/x/sync/errgroup"
)

type (
	// fetchFunc knows how to fetch a scannerResource from a pod and pack the response into an envelope.
	fetcherFunc func(context.Context, string, string, scannerResource, string) (hostsensor.HostSensorDataEnvelope, error)

	// workerResult holds the response from the scanner API.
	workerResult struct {
		Kind    scannerResource
		Payload hostsensor.HostSensorDataEnvelope
		Err     error
	}

	// workerPool propagates requests asynchronously to all registered pods.
	workerPool struct {
		workers *errgroup.Group
		results chan workerResult
		fetcher fetcherFunc
		ctx     context.Context

		*poolOptions
	}

	// poolOption specifies the configuration of the worker pool.
	poolOption func(*poolOptions)

	poolOptions struct {
		podMap     map[string]string
		maxWorkers int
	}
)

// poolWithMaxWorkers sets the maximum number of go routines to spawn.
//
// The default is 10.
func poolWithMaxWorkers(maxWorkers int) poolOption {
	return func(o *poolOptions) {
		o.maxWorkers = maxWorkers
	}
}

// poolWithPods registers the map of pod names to node names to be queried by the pool.
func poolWithPods(podMap map[string]string) poolOption {
	return func(o *poolOptions) {
		o.podMap = podMap
	}
}

func (r workerResult) IsEmpty() bool {
	return len(r.Payload.GetData()) == 0
}

// newWorkerPool creates a pool of go routines to apply the fetcherFunc on registered pods and post the responses in the Results() channel.
func newWorkerPool(parentCtx context.Context, fetcher fetcherFunc, opts ...poolOption) *workerPool {
	workersGroup, ctx := errgroup.WithContext(parentCtx)
	wp := &workerPool{
		poolOptions: poolOptionsWithDefaults(opts),
		fetcher:     fetcher,
		workers:     workersGroup,
		ctx:         ctx,
	}

	wp.workers.SetLimit(wp.maxWorkers)
	wp.results = make(chan workerResult)

	return wp
}

func poolOptionsWithDefaults(opts []poolOption) *poolOptions {
	o := &poolOptions{
		maxWorkers: 10,
	}

	for _, apply := range opts {
		apply(o)
	}

	return o
}

func (wp *workerPool) Results() <-chan workerResult {
	return wp.results
}

// Close the worker pool, waiting on all outstanding requests to complete and closing the results channel.
func (wp *workerPool) Close() error {
	defer func() {
		close(wp.results)
	}()

	return wp.workers.Wait()
}

// QueryPods asynchronously sends a request kind to all the pods registered for this workerPool.
// It errors if the pool's context is cancelled.
//
// Responses are returned to the Results() channel, possibly with an error from the API.
//
// QueryPods runs as many workers as necessary, within the limit of the maximum allowed workers.
//
// Requests are interrupted if the worker pool's context is cancelled.
func (wp *workerPool) QueryPods(requestKind scannerResource) error {
	for k, v := range wp.podMap {
		podName := k
		nodeName := v

		wp.workers.Go(func() error {
			hostSensorDataEnvelope, err := wp.fetcher(wp.ctx, podName, nodeName, requestKind, requestKind.Path())
			if err != nil {
				err = fmt.Errorf(
					"path: %s, node: %s, pod: %s: %w",
					requestKind.Path(), nodeName, podName, err,
				)
			}

			select {
			case <-wp.ctx.Done():
				return wp.ctx.Err()
			case wp.results <- workerResult{
				Kind:    requestKind,
				Payload: hostSensorDataEnvelope,
				Err:     err,
			}:
			}

			return nil
		})
	}

	return nil
}
