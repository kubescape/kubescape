package cautils

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	streamingspdy "k8s.io/streaming/pkg/httpstream/spdy"
)

const (
	// DefaultPortForwardPortEnv is the environment variable to configure the local port forwarder port.
	DefaultPortForwardPortEnv string = "DEFAULT_PORT_FORWARDER_PORT"
	// DefaultPortForwardPortValue is the default local port if DefaultPortForwardPortEnv is not set.
	DefaultPortForwardPortValue string = "4444"

	// PortForwardReadyTimeoutEnv overrides the default port-forward readiness timeout.
	// The value should be a positive integer representing seconds.
	PortForwardReadyTimeoutEnv string = "KS_PORT_FORWARD_READY_TIMEOUT_SECONDS"
	// defaultPortForwardReadyTimeout is the default duration to wait for port-forward readiness.
	defaultPortForwardReadyTimeout time.Duration = 30 * time.Second

	// maxPortForwardReadyTimeoutSeconds is the maximum seconds value
	// PortForwardReadyTimeoutEnv can hold without overflowing time.Duration
	// (an int64 nanosecond count) when multiplied by time.Second. Anything
	// above this wraps to a negative duration.
	maxPortForwardReadyTimeoutSeconds int64 = math.MaxInt64 / int64(time.Second)
)

// handshakeConnHolder holds a reference to the dialed connection during the SPDY handshake
// so that the readiness deadline can be cleared once readiness is confirmed.
type handshakeConnHolder struct {
	mu   sync.Mutex
	conn net.Conn
}

func (h *handshakeConnHolder) store(conn net.Conn) {
	h.mu.Lock()
	h.conn = conn
	h.mu.Unlock()
}

func (h *handshakeConnHolder) clearDeadline() {
	h.mu.Lock()
	conn := h.conn
	h.mu.Unlock()
	if conn != nil {
		_ = conn.SetDeadline(time.Time{})
	}
}

type portForward struct {
	*portforward.PortForwarder
	localPort     string
	stopChan      chan struct{}
	stopOnce      sync.Once
	readyChan     chan struct{}
	errChan       chan error
	out           *bytes.Buffer
	errOut        *bytes.Buffer
	readyTimeout  time.Duration
	handshakeConn *handshakeConnHolder
}

func getPortForwardingPort() string {
	if port, exist := os.LookupEnv(DefaultPortForwardPortEnv); exist {
		return port
	}
	return DefaultPortForwardPortValue
}

// getPortForwardReadyTimeout resolves the readiness timeout from KS_PORT_FORWARD_READY_TIMEOUT_SECONDS,
// falling back to defaultPortForwardReadyTimeout if unset, invalid, negative, or overflowing.
func getPortForwardReadyTimeout() time.Duration {
	if raw, exist := os.LookupEnv(PortForwardReadyTimeoutEnv); exist {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 && int64(secs) <= maxPortForwardReadyTimeoutSeconds {
			return time.Duration(secs) * time.Second
		}
	}
	return defaultPortForwardReadyTimeout
}

func splitServerURL(host string) (string, string, string, error) {
	if host == "" {
		return "https", "", "", nil
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}

	baseURL, err := url.Parse(host)
	if err != nil {
		return "", "", "", err
	}

	return baseURL.Scheme, baseURL.Host, strings.TrimRight(baseURL.Path, "/"), nil
}

// newPortForwardRoundTripper builds the round tripper and upgrader used to
// dial the SPDY upgrade request. It arms a deadline on the raw dialed
// connection so that a stalled SPDY handshake read (http.ReadResponse) does not
// block indefinitely. The deadline is cleared once readiness succeeds.
// If a proxy applies, it falls back to the standard RoundTripperFor.
func newPortForwardRoundTripper(config *rest.Config, serverURL *url.URL, readyTimeout time.Duration) (http.RoundTripper, spdy.Upgrader, *handshakeConnHolder, error) {
	proxyFunc := http.ProxyFromEnvironment
	if config.Proxy != nil {
		proxyFunc = config.Proxy
	}
	probeReq, err := http.NewRequest(http.MethodGet, serverURL.String(), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	proxyURL, err := proxyFunc(probeReq)
	if err != nil {
		return nil, nil, nil, err
	}
	if proxyURL != nil {
		roundTripper, upgrader, err := spdy.RoundTripperFor(config)
		return roundTripper, upgrader, nil, err
	}

	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, nil, nil, err
	}

	handshakeConn := &handshakeConnHolder{}
	upgradeTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if err := conn.SetDeadline(time.Now().Add(readyTimeout)); err != nil {
				conn.Close()
				return nil, err
			}
			handshakeConn.store(conn)
			return conn, nil
		},
	}

	spdyRoundTripper, err := streamingspdy.NewRoundTripperWithConfig(streamingspdy.RoundTripperConfig{
		PingPeriod:       time.Second * 5,
		UpgradeTransport: upgradeTransport,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	roundTripper, err := rest.HTTPWrappersForConfig(config, spdyRoundTripper)
	if err != nil {
		return nil, nil, nil, err
	}
	return roundTripper, spdy.NewUpgraderForStreaming(spdyRoundTripper), handshakeConn, nil
}

// CreatePortForwarder creates an OperatorConnector instance configured for port-forwarding to a pod.
func CreatePortForwarder(k8sClient *k8sinterface.KubernetesApi, pod *v1.Pod, forwardingPort, namespace string) (OperatorConnector, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod.Name)
	scheme, hostIP, basePath, err := splitServerURL(k8sClient.K8SConfig.Host)
	if err != nil {
		return nil, err
	}
	serverURL := &url.URL{Scheme: scheme, Path: basePath + path, Host: hostIP}

	readyTimeout := getPortForwardReadyTimeout()

	roundTripper, upgrader, handshakeConn, err := newPortForwardRoundTripper(k8sClient.K8SConfig, serverURL, readyTimeout)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper, Timeout: readyTimeout}, http.MethodPost, serverURL)
	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)

	// Resolve the requested port once, so the forwarder and the fallback in
	// GetPortForwardLocalhost cannot disagree if the environment changes.
	localPort := getPortForwardingPort()

	forwarder, err := portforward.NewOnAddresses(dialer, []string{"localhost"}, []string{fmt.Sprintf("%s:%s", localPort, forwardingPort)}, stopChan, readyChan, out, errOut)
	if err != nil {
		return nil, err
	}

	return &portForward{
		PortForwarder: forwarder,
		localPort:     localPort,
		stopChan:      stopChan,
		readyChan:     readyChan,
		errChan:       make(chan error, 1),
		out:           out,
		errOut:        errOut,
		readyTimeout:  readyTimeout,
		handshakeConn: handshakeConn,
	}, nil
}

// waitForPortForwardReadiness waits for the port-forward to become ready or fail, bounded by readyTimeout.
func (p *portForward) waitForPortForwardReadiness() error {
	timer := time.NewTimer(p.readyTimeout)
	defer timer.Stop()

	select {
	case <-p.readyChan:
		if p.handshakeConn != nil {
			p.handshakeConn.clearDeadline()
		}
		return nil
	case err := <-p.errChan:
		if err == nil {
			err = fmt.Errorf("port-forward exited before becoming ready: %s", strings.TrimSpace(p.errOut.String()))
		}
		return err
	case <-timer.C:
		p.StopPortForwarder()
		errMsg := strings.TrimSpace(p.errOut.String())
		if errMsg != "" {
			return fmt.Errorf("timed out after %s waiting for the port-forward to the Kubescape Operator pod to become ready: %s (override the wait with %s)", p.readyTimeout, errMsg, PortForwardReadyTimeoutEnv)
		}
		return fmt.Errorf("timed out after %s waiting for the port-forward to the Kubescape Operator pod to become ready; check network connectivity to the API server and that the operator pod is reachable (override the wait with %s)", p.readyTimeout, PortForwardReadyTimeoutEnv)
	}
}

// GetPortForwardLocalhost reports the bound port, which differs from the
// requested one when DEFAULT_PORT_FORWARDER_PORT is 0. GetPorts() errors out
// until the listeners are ready, hence the fallback.
func (p *portForward) GetPortForwardLocalhost() string {
	if ports, err := p.GetPorts(); err == nil && len(ports) > 0 {
		return fmt.Sprintf("localhost:%d", ports[0].Local)
	}
	return "localhost:" + p.localPort
}

// StopPortForwarder safely terminates the port forwarder by closing the stop channel idempotently.
func (p *portForward) StopPortForwarder() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
}

// StartPortForwarder starts port forwarding in a background goroutine and waits for readiness.
func (p *portForward) StartPortForwarder() error {
	go func() {
		p.errChan <- p.ForwardPorts()
	}()
	return p.waitForPortForwardReadiness()
}
