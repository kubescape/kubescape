package hostsensorutils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostSensorHandlerMock(t *testing.T) {
	ctx := context.Background()
	h := NewHostSensorHandlerMock()
	require.NotNil(t, h)

	require.NoError(t, h.Init(ctx))

	envelope, status, partials, err := h.CollectResources(ctx)
	require.Empty(t, envelope)
	require.Nil(t, status)
	require.Empty(t, partials)
	require.NoError(t, err)

	require.NoError(t, h.TearDown())
}
