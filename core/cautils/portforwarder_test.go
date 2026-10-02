package cautils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
		name        string
		primaryEnv  string
		setPrimary  bool
		fallbackEnv string
		setFallback bool
		want        time.Duration
	}{
		{
			name: "unset falls back to default",
			want: defaultPortForwardReadyTimeout,
		},
		{
			name:       "valid primary override is honored",
			setPrimary: true,
			primaryEnv: "5",
			want:       5 * time.Second,
		},
		{
			name:        "fallback env integer seconds is honored when primary unset",
			setFallback: true,
			fallbackEnv: "15",
			want:        15 * time.Second,
		},
		{
			name:        "fallback env duration string is honored when primary unset",
			setFallback: true,
			fallbackEnv: "25s",
			want:        25 * time.Second,
		},
		{
			name:        "primary takes precedence over fallback",
			setPrimary:  true,
			primaryEnv:  "10",
			setFallback: true,
			fallbackEnv: "20s",
			want:        10 * time.Second,
		},
		{
			name:       "zero falls back to default rather than firing instantly",
			setPrimary: true,
			primaryEnv: "0",
			want:       defaultPortForwardReadyTimeout,
		},
		{
			name:       "negative falls back to default",
			setPrimary: true,
			primaryEnv: "-5",
			want:       defaultPortForwardReadyTimeout,
		},
		{
			name:       "non-numeric falls back to default",
			setPrimary: true,
			primaryEnv: "soon",
			want:       defaultPortForwardReadyTimeout,
		},
		{
			name:       "value overflowing time.Duration falls back to default",
			setPrimary: true,
			primaryEnv: "9223372037",
			want:       defaultPortForwardReadyTimeout,
		},
		{
			name:       "largest non-overflowing value is honored",
			setPrimary: true,
			primaryEnv: strconv.FormatInt(maxPortForwardReadyTimeoutSeconds, 10),
			want:       time.Duration(maxPortForwardReadyTimeoutSeconds) * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setPrimary {
				t.Setenv(PortForwardReadyTimeoutEnv, tc.primaryEnv)
			} else {
				t.Setenv(PortForwardReadyTimeoutEnv, "")
			}
			if tc.setFallback {
				t.Setenv(DefaultPortForwardTimeoutEnv, tc.fallbackEnv)
			} else {
				t.Setenv(DefaultPortForwardTimeoutEnv, "")
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

func TestCreatePortForwarder_ProxyConfiguredArmsHandshakeDeadline(t *testing.T) {
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
	assert.NotNil(t, pf.handshakeConn, "a configured proxy must arm a handshake-level deadline")
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

func Test_waitForPortForwardReadiness_ClearsDeadlineOnReady(t *testing.T) {
	readyChan := make(chan struct{})
	close(readyChan)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Set a very short initial deadline that would expire quickly if not cleared
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(50*time.Millisecond)))

	holder := &handshakeConnHolder{}
	holder.store(clientConn)

	p := &portForward{
		stopChan:      make(chan struct{}),
		readyChan:     readyChan,
		errChan:       make(chan error, 1),
		out:           new(bytes.Buffer),
		errOut:        new(bytes.Buffer),
		readyTimeout:  5 * time.Second,
		handshakeConn: holder,
	}

	err := p.waitForPortForwardReadiness()
	require.NoError(t, err)

	// Wait past the original 50ms deadline to prove SetDeadline(time.Time{}) cleared it
	time.Sleep(100 * time.Millisecond)

	ioDone := make(chan struct{})
	go func() {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(serverConn, buf)
		_, _ = serverConn.Write([]byte("pong"))
		close(ioDone)
	}()

	_, writeErr := clientConn.Write([]byte("ping"))
	require.NoError(t, writeErr, "socket write should succeed after deadline is cleared")

	readBuf := make([]byte, 4)
	_, readErr := io.ReadFull(clientConn, readBuf)
	require.NoError(t, readErr, "socket read should succeed past the original deadline without i/o timeout")
	assert.Equal(t, "pong", string(readBuf))

	<-ioDone
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
		require.Error(t, err, "server should observe the client closing the stalled connection")
		var netErr net.Error
		if errors.As(err, &netErr) {
			assert.False(t, netErr.Timeout(), "read error should be connection closure (e.g. EOF or reset), not a read timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted a connection")
	}
}

func TestStartPortForwarder_DirectHTTPSUntrustedCertRejected(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Default rest.Config without custom CA or Insecure flag: relies on system roots
	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{Host: ts.URL},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	err = connector.StartPortForwarder()
	require.Error(t, err, "untrusted self-signed certificate must be rejected")
	assert.Contains(t, err.Error(), "certificate signed by unknown authority")
}

func TestStartPortForwarder_DirectHTTPSTrustedCertAccepted(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler receives request; withhold response so it times out cleanly at readiness
	}))
	defer ts.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ts.Certificate().Raw,
	})

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	// Provide the test server's certificate via CAData
	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: ts.URL,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: certPEM,
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	err = connector.StartPortForwarder()
	require.Error(t, err)
	// Certificate is trusted, so TLS handshake succeeds; error is not an x509 verification failure
	assert.NotContains(t, err.Error(), "certificate signed by unknown authority")
	assert.NotContains(t, err.Error(), "x509: certificate")
}

func TestStartPortForwarder_HTTPSProxyUntrustedCertRejected(t *testing.T) {
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	// Default rest.Config without proxy certificate in CAData
	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "http://10.96.0.1:80",
			Proxy: func(*http.Request) (*url.URL, error) {
				return proxyURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	err = connector.StartPortForwarder()
	require.Error(t, err, "untrusted self-signed certificate on HTTPS proxy must be rejected")
	assert.Contains(t, err.Error(), "certificate signed by unknown authority")
}

func TestStartPortForwarder_HTTPSProxyTrustedCertAccepted(t *testing.T) {
	var connectReached atomic.Bool
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connectReached.Store(true)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer clientConn.Close()

			_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			time.Sleep(500 * time.Millisecond)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: proxyServer.Certificate().Raw,
	})

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	// Supply the proxy's TLS certificate in CAData
	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "http://10.96.0.1:80",
			TLSClientConfig: rest.TLSClientConfig{
				CAData: certPEM,
			},
			Proxy: func(*http.Request) (*url.URL, error) {
				return proxyURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.True(t, connectReached.Load(), "HTTPS proxy CONNECT endpoint must be reached")
	// Because proxy certificate in CAData is trusted, the HTTPS proxy TLS handshake succeeds
	assert.NotContains(t, err.Error(), "certificate signed by unknown authority")
	assert.NotContains(t, err.Error(), "x509: certificate")
}

func TestStartPortForwarder_ProxiedStalledHandshakeTerminatesSocket(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyLn.Close()

	proxyConnChan := make(chan net.Conn, 1)
	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		// Accept connection, but withhold any response to the HTTP CONNECT request
		proxyConnChan <- conn
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	proxyURL, err := url.Parse("http://" + proxyLn.Addr().String())
	require.NoError(t, err)

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "https://10.96.0.1:443",
			Proxy: func(*http.Request) (*url.URL, error) {
				return proxyURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	start := time.Now()
	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "must not hang past readyTimeout on stalled proxy")

	select {
	case conn := <-proxyConnChan:
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		var readErr error
		for {
			_, readErr = conn.Read(buf)
			if readErr != nil {
				break
			}
		}
		require.Error(t, readErr, "proxy should observe the client closing the stalled connection")
		var netErr net.Error
		if errors.As(readErr, &netErr) {
			assert.False(t, netErr.Timeout(), "read error should be connection closure (e.g. EOF or reset), not a read timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never accepted a connection")
	}
}

func TestStartPortForwarder_ProxiedWithheldUpgradeTerminatesSocket(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyLn.Close()

	proxyConnChan := make(chan net.Conn, 1)
	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		// Read CONNECT request and reply 200 OK
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			conn.Close()
			return
		}
		if req.Method == http.MethodConnect {
			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}
		// Now withhold the SPDY upgrade response completely
		proxyConnChan <- conn
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	proxyURL, err := url.Parse("http://" + proxyLn.Addr().String())
	require.NoError(t, err)

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "http://10.96.0.1:80",
			Proxy: func(*http.Request) (*url.URL, error) {
				return proxyURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	start := time.Now()
	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "must not hang past readyTimeout when upstream withholds upgrade through proxy")

	select {
	case conn := <-proxyConnChan:
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		var readErr error
		for {
			_, readErr = conn.Read(buf)
			if readErr != nil {
				break
			}
		}
		require.Error(t, readErr, "proxy should observe the client closing the connection after timeout")
		var netErr net.Error
		if errors.As(readErr, &netErr) {
			assert.False(t, netErr.Timeout(), "read error should be connection closure (e.g. EOF or reset), not a read timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never accepted a connection")
	}
}

func TestStartPortForwarder_HTTPProxyCONNECT_FramingHeadersIgnored(t *testing.T) {
	testCases := []struct {
		name        string
		connectResp string
	}{
		{
			name:        "Content-Length non-zero header",
			connectResp: "HTTP/1.1 200 Connection Established\r\nContent-Length: 42\r\n\r\n",
		},
		{
			name:        "Transfer-Encoding chunked header",
			connectResp: "HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n",
		},
		{
			name:        "Content-Length zero header",
			connectResp: "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer proxyLn.Close()

			receivedUpgradeChan := make(chan string, 1)
			go func() {
				conn, err := proxyLn.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				// Read CONNECT request and reply with 200 OK containing framing headers per RFC 9110 §9.3.6 test case
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Method == http.MethodConnect {
					_, _ = conn.Write([]byte(tc.connectResp))
				}

				// The client must not block or drain/fail. It should proceed to send the SPDY upgrade request through the tunnel.
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				upgradeReq, err := http.ReadRequest(br)
				if err == nil {
					receivedUpgradeChan <- upgradeReq.Method + " " + upgradeReq.URL.Path
				}
			}()

			t.Setenv(PortForwardReadyTimeoutEnv, "1")

			proxyURL, err := url.Parse("http://" + proxyLn.Addr().String())
			require.NoError(t, err)

			k8sClient := &k8sinterface.KubernetesApi{
				K8SConfig: &rest.Config{
					Host: "http://10.96.0.1:80",
					Proxy: func(*http.Request) (*url.URL, error) {
						return proxyURL, nil
					},
				},
			}
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
			connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
			require.NoError(t, err)

			_ = connector.StartPortForwarder()

			select {
			case reqLine := <-receivedUpgradeChan:
				assert.Contains(t, reqLine, "POST /api/v1/namespaces/kubescape/pods/operator/portforward")
			case <-time.After(2 * time.Second):
				t.Fatal("proxy never received the SPDY upgrade request over the CONNECT tunnel due to framing header handling")
			}
		})
	}
}

func TestStartPortForwarder_SOCKS5ProxyStalledHandshakeTerminatesSocket(t *testing.T) {
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer socksLn.Close()

	socksConnChan := make(chan net.Conn, 1)
	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		// Accept connection, but withhold any response to the SOCKS5 handshake
		socksConnChan <- conn
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	socksURL, err := url.Parse("socks5://" + socksLn.Addr().String())
	require.NoError(t, err)

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "http://10.96.0.1:80",
			Proxy: func(*http.Request) (*url.URL, error) {
				return socksURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	start := time.Now()
	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "must not hang past readyTimeout on stalled SOCKS5 proxy")

	select {
	case conn := <-socksConnChan:
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		var readErr error
		for {
			_, readErr = conn.Read(buf)
			if readErr != nil {
				break
			}
		}
		require.Error(t, readErr, "socks proxy should observe the client closing the connection after timeout")
		var netErr net.Error
		if errors.As(readErr, &netErr) {
			assert.False(t, netErr.Timeout(), "read error should be connection closure (e.g. EOF or reset), not a read timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("socks proxy never accepted a connection")
	}
}

func TestStartPortForwarder_SOCKS5ProxyWithheldUpgradeTerminatesSocket(t *testing.T) {
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer socksLn.Close()

	socksConnChan := make(chan net.Conn, 1)
	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		// Read SOCKS5 greeting: 0x05, NMETHODS, METHODS...
		greetingHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, greetingHeader); err != nil || greetingHeader[0] != 0x05 {
			conn.Close()
			return
		}
		methods := make([]byte, int(greetingHeader[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			conn.Close()
			return
		}
		// Reply NO AUTHENTICATION REQUIRED (0x05, 0x00)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			conn.Close()
			return
		}

		// Read SOCKS5 CONNECT request: 0x05 (VER), 0x01 (CMD CONNECT), 0x00 (RSV), ATYP
		reqHeader := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHeader); err != nil || reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
			conn.Close()
			return
		}
		var addrLen int
		switch reqHeader[3] {
		case 0x01: // IPv4: 4 bytes addr + 2 bytes port
			addrLen = 6
		case 0x03: // Domain name: 1 byte len + N bytes domain + 2 bytes port
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				conn.Close()
				return
			}
			addrLen = int(lenBuf[0]) + 2
		case 0x04: // IPv6: 16 bytes addr + 2 bytes port
			addrLen = 18
		default:
			conn.Close()
			return
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			conn.Close()
			return
		}
		// Reply SUCCESS: 0x05, 0x00 (success), 0x00 (rsv), 0x01 (IPv4), 0,0,0,0 (addr), 0,0 (port)
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
			conn.Close()
			return
		}

		// Now withhold the SPDY upgrade response completely
		socksConnChan <- conn
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1")

	socksURL, err := url.Parse("socks5://" + socksLn.Addr().String())
	require.NoError(t, err)

	k8sClient := &k8sinterface.KubernetesApi{
		K8SConfig: &rest.Config{
			Host: "http://10.96.0.1:80",
			Proxy: func(*http.Request) (*url.URL, error) {
				return socksURL, nil
			},
		},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}
	connector, err := CreatePortForwarder(k8sClient, pod, "1234", "kubescape")
	require.NoError(t, err)

	start := time.Now()
	err = connector.StartPortForwarder()
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second, "must not hang past readyTimeout when upstream withholds upgrade through SOCKS5")

	select {
	case conn := <-socksConnChan:
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 1024)
		var readErr error
		for {
			_, readErr = conn.Read(buf)
			if readErr != nil {
				break
			}
		}
		require.Error(t, readErr, "socks proxy should observe the client closing the connection after timeout")
		var netErr net.Error
		if errors.As(readErr, &netErr) {
			assert.False(t, netErr.Timeout(), "read error should be connection closure (e.g. EOF or reset), not a read timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("socks proxy never accepted a connection")
	}
}

func Test_canonicalAddr_SOCKS5DefaultPort(t *testing.T) {
	testCases := []struct {
		urlStr   string
		expected string
	}{
		{"socks5://proxy.example.com", "proxy.example.com:1080"},
		{"socks5h://proxy.example.com", "proxy.example.com:1080"},
		{"socks5://proxy.example.com:1085", "proxy.example.com:1085"},
		{"http://proxy.example.com", "proxy.example.com:80"},
		{"https://proxy.example.com", "proxy.example.com:443"},
	}

	for _, tc := range testCases {
		t.Run(tc.urlStr, func(t *testing.T) {
			u, err := url.Parse(tc.urlStr)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, canonicalAddr(u))
		})
	}
}
