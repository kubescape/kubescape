package cautils

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
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

type portForward struct {
	*portforward.PortForwarder
	localPort    string
	stopChan     chan struct{}
	stopOnce     sync.Once
	readyChan    chan struct{}
	errChan      chan error
	out          *bytes.Buffer
	errOut       *bytes.Buffer
	readyTimeout time.Duration
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

	roundTripper, upgrader, err := spdy.RoundTripperFor(k8sClient.K8SConfig)
	if err != nil {
		return nil, err
	}

	// Resolve the readiness budget once, before the dialer is built, so the
	// same value bounds both the initial SPDY upgrade dial (an ordinary HTTP
	// request the returned client's Timeout already covers) and the
	// waitForPortForwardReadiness fallback below, which exists for the case
	// the dial succeeds but the port-forward never signals ready.
	readyTimeout := getPortForwardReadyTimeout()
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
	}, nil
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
