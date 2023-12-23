package getter

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	utils "github.com/kubescape/backend/pkg/utils"
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
		require.EqualValues(t, empty, GetKSCloudAPIConnector())
	})

	t.Run("initialized global connector should yield the same pointer", func(t *testing.T) {
		ksCloud, _ := v1.NewKSCloudAPI("test-123", "test-456", "account", "token")
		SetKSCloudAPIConnector(ksCloud)

		client := GetKSCloudAPIConnector()
		require.Equal(t, ksCloud, client)
		require.Equal(t, client, GetKSCloudAPIConnector())
	})
}

func TestHttpPost(t *testing.T) {
	client := http.DefaultClient
	hdrs := map[string]string{"key": "value"}

	srv := mockAPIServer(t)
	t.Cleanup(srv.Close)

	t.Run("HttpPost should POST", func(t *testing.T) {
		type VersionCheckResponse struct {
			Client          string  `json:"client"`          // kubescape
			ClientUpdate    string  `json:"clientUpdate"`    // kubescape latest version
			Framework       float32 `json:"framework"`       // framework name
			FrameworkUpdate int64   `json:"frameworkUpdate"` // framework latest version
			Message         string  `json:"message"`         // alert message
		}
		body := &VersionCheckResponse{
			Client:          "kubescape",
			ClientUpdate:    "v3.0.0",
			Framework:       45.3,
			FrameworkUpdate: 29,
			Message:         "",
		}

		reqBody, err := json.Marshal(*body)
		require.NoError(t, err)

		resp, _, err := HTTPPost(client, srv.URL(pathTestPost), reqBody, hdrs)
		require.NoError(t, err)

		respString, err := utils.Decode[*VersionCheckResponse](resp)
		require.NoError(t, err)
		require.Equal(t, body, respString)
	})
}

type testServer struct {
	*httptest.Server
}

func (s *testServer) URL(pth string) string {
	pth = strings.TrimLeft(pth, "/")

	return fmt.Sprintf("%s/%s", s.Server.URL, pth)
}

func mockAPIServer(t testing.TB) *testServer {
	h := http.NewServeMux()

	// test options: regular mock (default), error or garbled JSON output
	server := &testServer{
		Server: httptest.NewServer(h),
	}

	h.HandleFunc(pathTestPost, func(w http.ResponseWriter, r *http.Request) {
		require.Truef(t, strings.EqualFold(http.MethodPost, r.Method), "expected a POST method called, but got %q", r.Method)
		// write a json response here
		defer func() { _ = r.Body.Close() }()
		_, _ = io.Copy(w, r.Body)

		return

	})

	return server
}
