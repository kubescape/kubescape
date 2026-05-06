package cautils

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	DefaultPortForwardPortEnv   string = "DEFAULT_PORT_FORWARDER_PORT"
	DefaultPortForwardPortValue string = "4444"
)

type portForward struct {
	*portforward.PortForwarder
	localPort string
	stopChan  chan struct{}
	readyChan chan struct{}
	errChan   chan error
	out       *bytes.Buffer
	errOut    *bytes.Buffer
}

func getPortForwardingPort() string {
	if port, exist := os.LookupEnv(DefaultPortForwardPortEnv); exist {
		return port
	}
	return DefaultPortForwardPortValue
}

func splitHostAndBasePath(host string) (string, string, error) {
	if !strings.Contains(host, "://") {
		return host, "", nil
	}

	baseURL, err := url.Parse(host)
	if err != nil {
		return "", "", err
	}

	return baseURL.Host, strings.TrimRight(baseURL.Path, "/"), nil
}

func CreatePortForwarder(k8sClient *k8sinterface.KubernetesApi, pod *v1.Pod, forwardingPort, namespace string) (OperatorConnector, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod.Name)
	hostIP, basePath, err := splitHostAndBasePath(k8sClient.K8SConfig.Host)
	if err != nil {
		return nil, err
	}
	serverURL := &url.URL{Scheme: "https", Path: basePath + path, Host: hostIP}

	roundTripper, upgrader, err := spdy.RoundTripperFor(k8sClient.K8SConfig)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, serverURL)
	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)

	forwarder, err := portforward.NewOnAddresses(dialer, []string{"localhost"}, []string{fmt.Sprintf("%s:%s", getPortForwardingPort(), forwardingPort)}, stopChan, readyChan, out, errOut)
	if err != nil {
		return nil, err
	}

	return &portForward{
		PortForwarder: forwarder,
		localPort:     getPortForwardingPort(),
		stopChan:      stopChan,
		readyChan:     readyChan,
		errChan:       make(chan error, 1),
		out:           out,
		errOut:        errOut,
	}, nil
}

func (p *portForward) waitForPortForwardReadiness() error {
	select {
	case <-p.readyChan:
		return nil
	case err := <-p.errChan:
		if err == nil {
			err = fmt.Errorf("port-forward exited before becoming ready: %s", strings.TrimSpace(p.errOut.String()))
		}
		return err
	}
}

func (p *portForward) GetPortForwardLocalhost() string {
	return "localhost:" + getPortForwardingPort()
}

func (p *portForward) StopPortForwarder() {
	p.stopChan <- struct{}{}
}

func (p *portForward) StartPortForwarder() error {
	go func() {
		p.errChan <- p.ForwardPorts()
	}()
	return p.waitForPortForwardReadiness()
}
