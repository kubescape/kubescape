package cautils

import (
	"bytes"
	"context"
	"fmt"
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
	apimachineryspdy "k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	DefaultPortForwardPortEnv   string = "DEFAULT_PORT_FORWARDER_PORT"
	DefaultPortForwardPortValue string = "4444"

	// PortForwardReadyTimeoutEnv overrides how long StartPortForwarder waits
	// for the port-forward to the operator pod to become ready before giving
	// up. Same override pattern as DefaultPortForwardPortEnv.
	PortForwardReadyTimeoutEnv string = "KS_PORT_FORWARD_READY_TIMEOUT_SECONDS"

	defaultPortForwardReadyTimeout time.Duration = 30 * time.Second
)

// handshakeConnHolder lets the custom DialContext (running inside the
// background ForwardPorts goroutine) hand the raw dialed connection back to
// waitForPortForwardReadiness (running on the caller's goroutine), so the
// read deadline armed for the handshake can be cleared once the upgrade
// actually succeeds -- otherwise it would still apply to the long-lived
// port-forward stream afterward.
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
	handshakeConn *handshakeConnHolder // nil when the proxy-fallback path was used
}

func getPortForwardingPort() string {
	if port, exist := os.LookupEnv(DefaultPortForwardPortEnv); exist {
		return port
	}
	return DefaultPortForwardPortValue
}

// getPortForwardReadyTimeout resolves the readiness-wait budget once per
// forwarder, mirroring getPortForwardingPort so the timeout used by
// waitForPortForwardReadiness and the one used to bound the dial itself
// cannot disagree if the environment changes mid-run.
func getPortForwardReadyTimeout() time.Duration {
	if raw, exist := os.LookupEnv(PortForwardReadyTimeoutEnv); exist {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
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

func CreatePortForwarder(k8sClient *k8sinterface.KubernetesApi, pod *v1.Pod, forwardingPort, namespace string) (OperatorConnector, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod.Name)
	scheme, hostIP, basePath, err := splitServerURL(k8sClient.K8SConfig.Host)
	if err != nil {
		return nil, err
	}
	serverURL := &url.URL{Scheme: scheme, Path: basePath + path, Host: hostIP}

	// Resolve the readiness budget once, before the dialer is built, so the
	// same value bounds both the initial SPDY upgrade dial (an ordinary HTTP
	// request the returned client's Timeout already covers) and the
	// waitForPortForwardReadiness fallback below, which exists for the case
	// the dial succeeds but the port-forward never signals ready.
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

// newPortForwardRoundTripper builds the round tripper and upgrader used to
// dial the SPDY upgrade request. Its own http.Client.Timeout only bounds the
// dial and the request write; the SPDY libraries' hand-rolled response read
// afterward (http.ReadResponse over a raw bufio reader) never checks that
// timeout, so a peer that completes TCP/TLS but withholds the upgrade
// response leaves that read -- and the goroutine and socket behind it --
// blocked forever. See PR #3800 review.
//
// When no proxy applies to serverURL, this arms a deadline on the raw dialed
// connection itself (via a custom DialContext plugged in as UpgradeTransport)
// so the stalled read is bounded too; the deadline persists through the TLS
// handshake and is cleared by waitForPortForwardReadiness once the upgrade
// actually succeeds. Setting UpgradeTransport replaces the SPDY library's own
// dialing -- including its proxy-CONNECT tunneling -- entirely, so when a
// proxy does apply this falls back to the unbounded-read path unchanged
// rather than reimplementing proxy tunneling here. That fallback keeps only
// the pre-existing http.Client.Timeout, which does not cover a stalled
// upgrade read: a disclosed, deliberate limitation, not an oversight.
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

	spdyUpgrader, err := apimachineryspdy.NewRoundTripperWithConfig(apimachineryspdy.RoundTripperConfig{
		PingPeriod:       time.Second * 5,
		UpgradeTransport: upgradeTransport,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	roundTripper, err := rest.HTTPWrappersForConfig(config, spdyUpgrader)
	if err != nil {
		return nil, nil, nil, err
	}
	return roundTripper, spdyUpgrader, handshakeConn, nil
}

// waitForPortForwardReadiness blocks until the port-forward is ready, fails,
// or readyTimeout elapses. Without the timer case this can hang forever: the
// dial's own Timeout (set in CreatePortForwarder) only bounds establishing
// the SPDY upgrade, not a peer that accepts the connection and then never
// completes it, or a ForwardPorts implementation that never closes readyChan
// or errChan on some other stall path. The timer case is what turns that
// silent hang into a diagnosable error instead.
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
		return fmt.Errorf(
			"timed out after %s waiting for the port-forward to the Kubescape Operator pod to become ready; "+
				"check network connectivity to the API server and that the operator pod is reachable "+
				"(override the wait with %s)",
			p.readyTimeout,
			PortForwardReadyTimeoutEnv,
		)
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

func (p *portForward) StartPortForwarder() error {
	go func() {
		p.errChan <- p.ForwardPorts()
	}()
	return p.waitForPortForwardReadiness()
}
