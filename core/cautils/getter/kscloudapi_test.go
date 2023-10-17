package getter

import (
	"os"
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/stretchr/testify/require"
)

const (
	// extra mock API routes

	pathTestPost   = "/test-post"
	pathTestDelete = "/test-delete"
	pathTestGet    = "/test-get"
)

var (
	globalMx sync.Mutex // a mutex to avoid data races on package globals while testing

	testOptions = []v1.KSCloudOption{
		v1.WithTrace(os.Getenv("DEBUG_TEST") != ""),
	}
)

func TestGlobalKSCloudAPIConnector(t *testing.T) {
	t.Parallel()

	globalMx.Lock()
	defer globalMx.Unlock()

	globalKSCloudAPIConnector = nil

	t.Run("uninitialized global connector should yield an empty KS client", func(t *testing.T) {
		empty := v1.NewEmptyKSCloudAPI()
		require.EqualValues(t, *empty, GetKSCloudAPIConnector())
	})

	t.Run("initialized global connector should yield the same pointer", func(t *testing.T) {
		ksCloud, _ := v1.NewKSCloudAPI("test-123", "test-456", "account", "token")
		SetKSCloudAPIConnector(ksCloud)

		client := GetKSCloudAPIConnector()
		require.Equal(t, ksCloud, &client)
		require.Equal(t, client, GetKSCloudAPIConnector())
	})
}
