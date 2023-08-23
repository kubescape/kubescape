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

	t.Run("uninitialized global connector should yield a prod-ready KS client", func(t *testing.T) {
		prod := NewKSCloudAPIProd()
		require.EqualValues(t, prod, GetKSCloudAPIConnector())
	})

	t.Run("initialized global connector should yield the same pointer", func(t *testing.T) {
		dev := NewKSCloudAPIDev()
		SetKSCloudAPIConnector(dev)

		client := GetKSCloudAPIConnector()
		require.Equal(t, dev, client)
		require.Equal(t, client, GetKSCloudAPIConnector())
	})
}

func TestKSCloudAPISmoke(t *testing.T) {
	t.Run("smoke-test constructors", func(t *testing.T) {
		require.NotNil(t, NewKSCloudAPIDev())
		require.NotNil(t, NewKSCloudAPIStaging())
		require.NotNil(t, NewKSCloudAPIProd())
	})
}
