package hostsensorutils

import (
	"context"
	"sync"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/require"
)

func TestWorkerPool(t *testing.T) {
	t.Run("should stop on cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pods := map[string]string{
			"pod1": "node1",
			"pod2": "node2",
		}
		latch := make(chan struct{})
		fetcher := func(ctx context.Context, _ string, _ string, _ scannerResource, _ string) (hostsensor.HostSensorDataEnvelope, error) {
			select {
			case <-latch:
			case <-ctx.Done():
			}

			return hostsensor.HostSensorDataEnvelope{}, ctx.Err()
		}
		var wg sync.WaitGroup

		pool := newWorkerPool(
			ctx,
			fetcher,
			poolWithPods(pods),
			poolWithMaxWorkers(len(pods)),
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range pool.Results() {
			}
		}()
		defer func() {
			wg.Wait()
		}()

		require.NoError(t, pool.QueryPods(LinuxKernelVariables))
		cancel()
		close(latch)

		err := pool.Close()
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	})
}
