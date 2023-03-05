package version

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkipChecker(t *testing.T) {
	v := NewSkipChecker()

	ctx := context.Background()
	require.NoError(t,
		v.CheckLatestVersion(ctx),
	)
}
