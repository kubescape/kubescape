package cautils

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// TestWaitForPortForwardReadiness_TimesOutInsteadOfHangingForever reproduces
// the hang: a port-forward whose dial never closes readyChan and never sends
// on errChan (e.g. the peer accepted the connection but never completed the
// SPDY upgrade). Before the readyTimeout case existed, this blocked forever.
func TestWaitForPortForwardReadiness_TimesOutInsteadOfHangingForever(t *testing.T) {
	p := &portForward{
		readyChan:    make(chan struct{}),
		errChan:      make(chan error),
		readyTimeout: 50 * time.Millisecond,
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	// The watchdog is a much longer, generous bound (matching
	// TestStopPortForwarder_Idempotent's pattern): if the fix regresses to an
	// unbounded select, this fails the test instead of hanging the suite.
	select {
	case err := <-done:
		elapsed := time.Since(start)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
		assert.Contains(t, err.Error(), PortForwardReadyTimeoutEnv)
		assert.Less(t, elapsed, 2*time.Second, "should return close to readyTimeout, not after it")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness hung past its readyTimeout")
	}
}

// TestWaitForPortForwardReadiness_ReadyBeforeTimeout is the happy-path
// regression check: the new timer must not delay or interfere with an
// ordinary successful readiness signal.
func TestWaitForPortForwardReadiness_ReadyBeforeTimeout(t *testing.T) {
	readyChan := make(chan struct{})
	p := &portForward{
		readyChan:    readyChan,
		errChan:      make(chan error, 1),
		readyTimeout: 5 * time.Second,
	}
	close(readyChan)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.Less(t, time.Since(start), 1*time.Second, "an already-ready forwarder must not wait on the timer")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness did not return for an already-ready forwarder")
	}
}

// TestWaitForPortForwardReadiness_ErrorBeforeTimeout: a fast ForwardPorts
// failure must still be reported as that failure, not masked by the timer.
func TestWaitForPortForwardReadiness_ErrorBeforeTimeout(t *testing.T) {
	errChan := make(chan error, 1)
	wantErr := assert.AnError
	errChan <- wantErr

	p := &portForward{
		readyChan:    make(chan struct{}),
		errChan:      errChan,
		readyTimeout: 5 * time.Second,
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- p.waitForPortForwardReadiness()
	}()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, wantErr)
		assert.Less(t, time.Since(start), 1*time.Second, "a fast ForwardPorts error must not wait on the timer")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPortForwardReadiness did not return for a fast ForwardPorts error")
	}
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(PortForwardReadyTimeoutEnv, tc.envValue)
			}
			assert.Equal(t, tc.want, getPortForwardReadyTimeout())
		})
	}
}

// TestCreatePortForwarder_ResolvesReadyTimeoutFromEnvOnce checks the
// forwarder actually carries the resolved timeout (not just that the helper
// function computes it correctly), and that, like localPort, it is captured
// once at construction rather than re-read later.
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

	// Mutating the environment after construction must not change the
	// already-resolved timeout, matching GetPortForwardLocalhost's existing
	// "resolved once" guarantee for localPort.
	t.Setenv(PortForwardReadyTimeoutEnv, "1")
	assert.Equal(t, 7*time.Second, pf.readyTimeout)
}

// TestStartPortForwarder_WithheldUpgradeTerminatesSocketNotJustCaller
// reproduces matthyx's PR #3800 review finding: k8s.io/streaming's
// SpdyRoundTripper.RoundTrip reads the upgrade response via a hand-rolled
// bufio/http.ReadResponse over the raw socket, which never checks the
// request context or the merged http.Client.Timeout. A peer that completes
// the TCP handshake and then withholds the upgrade response left that read
// -- and the goroutine and socket behind it -- blocked forever, even though
// waitForPortForwardReadiness's own timer correctly returned an error to the
// caller. This proves both sides now unblock: the caller via the returned
// error, and the socket via the deadline armed in newPortForwardRoundTripper.
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
		// Read and parse the upgrade request, then withhold the response
		// entirely -- simulating a peer that completes the TCP handshake
		// but never finishes the SPDY upgrade.
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		serverConn <- conn
		// deliberately: no response written, connection left open
	}()

	t.Setenv(PortForwardReadyTimeoutEnv, "1") // 1s, keep the test fast

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

	// Prove the SERVER side observes the connection actually close/reset --
	// not just that the caller gave up. This is what distinguishes this test
	// from the existing timeout tests, which only check the caller side.
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

// TestCreatePortForwarder_ProxyConfiguredUsesFallbackPath is the sanity check
// for the deliberate scope boundary in newPortForwardRoundTripper: setting
// UpgradeTransport (needed to arm the handshake deadline) bypasses the SPDY
// library's own proxy-CONNECT tunneling entirely, so when a proxy applies to
// the target, CreatePortForwarder must fall back to the unmodified
// spdy.RoundTripperFor path -- not silently use the deadline path without
// proxy support, and not error out.
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
			Name:   "first",
			Labels: map[string]string{"app": "operator"},
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
