package cautils

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type FakeCachedDiscoveryClient struct {
	discovery.DiscoveryInterface
	Groups             []*metav1.APIGroup
	Resources          []*metav1.APIResourceList
	PreferredResources []*metav1.APIResourceList
	Invalidations      int
}

func Test_splitServerURL(t *testing.T) {
	testCases := []struct {
		name         string
		host         string
		wantScheme   string
		wantHost     string
		wantBasePath string
		wantErr      bool
	}{
		{
			name:       "https scheme is preserved",
			host:       "https://1.2.3.4:6443",
			wantScheme: "https",
			wantHost:   "1.2.3.4:6443",
		},
		{
			name:       "http scheme is preserved",
			host:       "http://1.2.3.4:6443",
			wantScheme: "http",
			wantHost:   "1.2.3.4:6443",
		},
		{
			name:       "host without scheme defaults to https",
			host:       "1.2.3.4:6443",
			wantScheme: "https",
			wantHost:   "1.2.3.4:6443",
		},
		{
			name:         "host without scheme preserves base path",
			host:         "proxy.example.com/k8s",
			wantScheme:   "https",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:       "empty host defaults to https",
			host:       "",
			wantScheme: "https",
			wantHost:   "",
		},
		{
			name:       "hostname starting with 'h' is preserved after https scheme",
			host:       "https://hello-cluster.example.com:6443",
			wantScheme: "https",
			wantHost:   "hello-cluster.example.com:6443",
		},
		{
			name:       "hostname starting with 't' is preserved after https scheme",
			host:       "https://test.example.com:6443",
			wantScheme: "https",
			wantHost:   "test.example.com:6443",
		},
		{
			name:       "hostname starting with 'p' is preserved after https scheme",
			host:       "https://prod.example.com",
			wantScheme: "https",
			wantHost:   "prod.example.com",
		},
		{
			name:       "hostname starting with 's' is preserved after https scheme",
			host:       "https://staging.example.com",
			wantScheme: "https",
			wantHost:   "staging.example.com",
		},
		{
			name:       "kubernetes.docker.internal is preserved",
			host:       "https://kubernetes.docker.internal:6443",
			wantScheme: "https",
			wantHost:   "kubernetes.docker.internal:6443",
		},
		{
			name:         "host with base path preserves path",
			host:         "https://proxy.example.com/k8s",
			wantScheme:   "https",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:         "http host with base path preserves both",
			host:         "http://proxy.example.com/k8s",
			wantScheme:   "http",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:         "host with port and base path preserves both",
			host:         "https://proxy.example.com:6443/k8s",
			wantScheme:   "https",
			wantHost:     "proxy.example.com:6443",
			wantBasePath: "/k8s",
		},
		{
			name:         "trailing slash on base path is trimmed",
			host:         "https://proxy.example.com/k8s/",
			wantScheme:   "https",
			wantHost:     "proxy.example.com",
			wantBasePath: "/k8s",
		},
		{
			name:         "multi-segment base path is preserved",
			host:         "https://proxy.example.com/api/v1/k8s",
			wantScheme:   "https",
			wantHost:     "proxy.example.com",
			wantBasePath: "/api/v1/k8s",
		},
		{
			name:    "malformed URL is rejected",
			host:    "https://proxy.example.com/%zz",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotScheme, gotHost, gotBasePath, err := splitServerURL(tc.host)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantScheme, gotScheme)
			assert.Equal(t, tc.wantHost, gotHost)
			assert.Equal(t, tc.wantBasePath, gotBasePath)
		})
	}
}

func TestCreatePortForwarder_HTTPServerReceivesPortForwardRequest(t *testing.T) {
	type receivedRequest struct {
		method string
		path   string
	}

	var requestCount atomic.Int32
	requests := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		select {
		case requests <- receivedRequest{method: r.Method, path: r.URL.Path}:
		default:
		}
		http.Error(w, "test server does not implement SPDY", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{Host: server.URL + "/proxy"},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	// The fake server deliberately rejects the SPDY upgrade. Reaching it proves
	// that the dialer used the explicit HTTP scheme from the kubeconfig.
	require.Error(t, connector.StartPortForwarder())
	require.Equal(t, int32(1), requestCount.Load())

	select {
	case got := <-requests:
		assert.Equal(t, http.MethodPost, got.method)
		assert.Equal(t, "/proxy/api/v1/namespaces/kubescape/pods/operator/portforward", got.path)
	default:
		t.Fatal("port-forward request did not reach the kubeconfig HTTP endpoint")
	}
}

func Test_getPortForwardingPort(t *testing.T) {
	testCases := []struct {
		name          string
		createNewPort bool
		port          string
		expectedPort  string
	}{
		{
			name:         "test default port",
			port:         "",
			expectedPort: DefaultPortForwardPortValue,
		},
		{
			name:          "test set port",
			createNewPort: true,
			port:          "1234",
			expectedPort:  "1234",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.createNewPort {
				t.Setenv(DefaultPortForwardPortEnv, tc.port)
			}
			assert.Equal(t, tc.expectedPort, getPortForwardingPort())
		})
	}
}

func Test_CreatePortForwarder(t *testing.T) {
	testCases := []struct {
		name          string
		expectedError error
	}{
		{
			name: "test creation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewClientset(),
				K8SConfig: &rest.Config{
					Host: "any",
				},
				Context: context.Background(),
			}

			operatorPod := v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "first",
					Labels: map[string]string{
						"app": "operator",
					},
				},
			}
			createdOperatorPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
			assert.Equal(t, nil, err)

			_, err = CreatePortForwarder(&k8sClient, createdOperatorPod, "1234", "any")
			assert.Equal(t, nil, err)

		})
	}
}

func Test_GetPortForwardLocalhost(t *testing.T) {
	testCases := []struct {
		name   string
		port   string
		result string
	}{
		{
			name:   "test creation",
			port:   "1234",
			result: "localhost",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sinterface.KubernetesApi{
				KubernetesClient: fake.NewClientset(),
				K8SConfig: &rest.Config{
					Host: "any",
				},
				Context: context.Background(),
			}

			operatorPod := v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "first",
					Labels: map[string]string{
						"app": "operator",
					},
				},
			}
			createdOperatorPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
			assert.Equal(t, nil, err)

			t.Setenv(DefaultPortForwardPortEnv, tc.port)
			pf, err := CreatePortForwarder(&k8sClient, createdOperatorPod, "1234", "any")
			assert.Equal(t, nil, err)

			result := pf.GetPortForwardLocalhost()
			assert.Equal(t, tc.result+":"+getPortForwardingPort(), result)
		})
	}
}

// TestStopPortForwarder_Idempotent verifies that repeated or concurrent calls to StopPortForwarder
// safely close the stop channel and never panic or block.
func TestStopPortForwarder_Idempotent(t *testing.T) {
	p := &portForward{
		stopChan: make(chan struct{}),
	}

	done := make(chan struct{})

	go func() {
		p.StopPortForwarder()
		p.StopPortForwarder()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StopPortForwarder blocked on repeated stop")
	}

	// Verify the channel was closed so all readers receive the stop broadcast
	select {
	case _, ok := <-p.stopChan:
		assert.False(t, ok, "stopChan must be closed")
	default:
		t.Fatal("stopChan was not closed by StopPortForwarder")
	}

	// Assert repeated calls do not panic
	assert.NotPanics(t, func() {
		p.StopPortForwarder()
		p.StopPortForwarder()
	})
}

func Test_getPortForwardReadyTimeout(t *testing.T) {
	testCases := []struct {
		name     string
		envValue string
		setEnv   bool
		want     time.Duration
	}{
		{
			name: "unset falls back to default",
			want: defaultPortForwardReadyTimeout,
		},
		{
			name:     "valid override is honored",
			setEnv:   true,
			envValue: "5",
			want:     5 * time.Second,
		},
		{
			name:     "zero falls back to default rather than firing instantly",
			setEnv:   true,
			envValue: "0",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "negative falls back to default",
			setEnv:   true,
			envValue: "-5",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "non-numeric falls back to default",
			setEnv:   true,
			envValue: "soon",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "value overflowing time.Duration falls back to default",
			setEnv:   true,
			envValue: "9223372037",
			want:     defaultPortForwardReadyTimeout,
		},
		{
			name:     "largest non-overflowing value is honored",
			setEnv:   true,
			envValue: strconv.FormatInt(maxPortForwardReadyTimeoutSeconds, 10),
			want:     time.Duration(maxPortForwardReadyTimeoutSeconds) * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(PortForwardReadyTimeoutEnv, tc.envValue)
			} else {
				t.Setenv(PortForwardReadyTimeoutEnv, "")
			}
			assert.Equal(t, tc.want, getPortForwardReadyTimeout())
		})
	}
}

func TestCreatePortForwarder_ResolvesReadyTimeoutFromEnvOnce(t *testing.T) {
	t.Setenv(PortForwardReadyTimeoutEnv, "7")

	k8sClient := k8sinterface.KubernetesApi{
		KubernetesClient: fake.NewClientset(),
		K8SConfig: &rest.Config{
			Host: "any",
		},
		Context: context.Background(),
	}

	operatorPod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first",
			Labels: map[string]string{
				"app": "operator",
			},
		},
	}
	createdPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
	require.NoError(t, err)

	connector, err := CreatePortForwarder(&k8sClient, createdPod, "1234", "any")
	require.NoError(t, err)

	pf, ok := connector.(*portForward)
	require.True(t, ok)
	assert.Equal(t, 7*time.Second, pf.readyTimeout)

	t.Setenv(PortForwardReadyTimeoutEnv, "1")
	assert.Equal(t, 7*time.Second, pf.readyTimeout)
}

func TestCreatePortForwarder_ProxyConfiguredUsesFallbackPath(t *testing.T) {
	k8sClient := k8sinterface.KubernetesApi{
		KubernetesClient: fake.NewClientset(),
		K8SConfig: &rest.Config{
			Host: "any",
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://proxy.example.com:8080")
			},
		},
		Context: context.Background(),
	}

	operatorPod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first",
			Labels: map[string]string{
				"app": "operator",
			},
		},
	}
	createdPod, err := k8sClient.KubernetesClient.CoreV1().Pods(kubescapeNamespace).Create(k8sClient.Context, &operatorPod, metav1.CreateOptions{})
	require.NoError(t, err)

	connector, err := CreatePortForwarder(&k8sClient, createdPod, "1234", "any")
	require.NoError(t, err)

	pf, ok := connector.(*portForward)
	require.True(t, ok)
	assert.Nil(t, pf.handshakeConn, "a configured proxy must take the fallback path without a handshake-level deadline")
}

func Test_waitForPortForwardReadiness_Timeout(t *testing.T) {
	p := &portForward{
		stopChan:     make(chan struct{}),
		readyChan:    make(chan struct{}),
		errChan:      make(chan error, 1),
		out:          new(bytes.Buffer),
		errOut:       bytes.NewBufferString("spdy connection handshake failed"),
		readyTimeout: 50 * time.Millisecond,
	}

	err := p.waitForPortForwardReadiness()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out after 50ms waiting for the port-forward to the Kubescape Operator pod to become ready")
	assert.Contains(t, err.Error(), "spdy connection handshake failed")

	// Ensure StopPortForwarder was called and stopChan was closed
	select {
	case <-p.stopChan:
		// success: stopChan is closed
	default:
		t.Fatal("expected stopChan to be closed on timeout")
	}
}

func Test_waitForPortForwardReadiness_Ready(t *testing.T) {
	readyChan := make(chan struct{})
	close(readyChan)

	p := &portForward{
		stopChan:     make(chan struct{}),
		readyChan:    readyChan,
		errChan:      make(chan error, 1),
		out:          new(bytes.Buffer),
		errOut:       new(bytes.Buffer),
		readyTimeout: 5 * time.Second,
	}

	err := p.waitForPortForwardReadiness()
	require.NoError(t, err)
}

func Test_waitForPortForwardReadiness_Error(t *testing.T) {
	errChan := make(chan error, 1)
	errChan <- fmt.Errorf("connection refused")

	p := &portForward{
		stopChan:     make(chan struct{}),
		readyChan:    make(chan struct{}),
		errChan:      errChan,
		out:          new(bytes.Buffer),
		errOut:       new(bytes.Buffer),
		readyTimeout: 5 * time.Second,
	}

	err := p.waitForPortForwardReadiness()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestStartPortForwarder_WithheldUpgradeTerminatesSocketNotJustCaller(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	serverConn := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read and parse the upgrade request, then withhold the response entirely
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		serverConn <- conn
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{Host: "http://" + ln.Addr().String()},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	start := time.Now()
	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "must not hang past readyTimeout")

	select {
	case conn := <-serverConn:
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		assert.Error(t, err, "server should observe the client closing the stalled connection")
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted a connection")
	}
}
