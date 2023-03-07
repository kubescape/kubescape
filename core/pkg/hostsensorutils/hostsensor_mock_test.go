package hostsensorutils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostSensorHandlerMock(t *testing.T) {
	ctx := context.Background()
	h := &HostSensorHandlerMock{}

	require.NoError(t, h.Init(ctx))

	envelope, status, err := h.CollectResources(ctx)
	require.Empty(t, envelope)
	require.Nil(t, status)
	require.NoError(t, err)

	require.Empty(t, h.GetNamespace())
	require.NoError(t, h.TearDown())
}
