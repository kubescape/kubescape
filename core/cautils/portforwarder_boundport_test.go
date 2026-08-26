package cautils

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/tools/portforward"
)

// The fakes below mirror the minimal httpstream surface that
// portforward.PortForwarder.ForwardPorts() needs in order to open its local
// listeners without talking to an API server. They are modelled on the
// equivalent helpers in client-go's own portforward tests.

type fakeStream struct {
	headers http.Header
}

func (*fakeStream) Read(p []byte) (int, error)  { return 0, nil }
func (*fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func (*fakeStream) Close() error                { return nil }
func (*fakeStream) Reset() error                { return nil }
func (s *fakeStream) Headers() http.Header      { return s.headers }
func (*fakeStream) Identifier() uint32          { return 0 }

type fakeConnection struct {
	closed    bool
	closeChan chan bool
}

func newFakeConnection() *fakeConnection {
	return &fakeConnection{closeChan: make(chan bool)}
}

func (c *fakeConnection) CreateStream(headers http.Header) (httpstream.Stream, error) {
	switch headers.Get(v1.StreamType) {
	case v1.StreamTypeData, v1.StreamTypeError:
		return &fakeStream{headers: headers}, nil
	default:
		return nil, fmt.Errorf("unsupported stream type %q", headers.Get(v1.StreamType))
	}
}

func (c *fakeConnection) Close() error {
	if !c.closed {
		c.closed = true
		close(c.closeChan)
	}
	return nil
}

func (c *fakeConnection) CloseChan() <-chan bool             { return c.closeChan }
func (c *fakeConnection) RemoveStreams(...httpstream.Stream) {}
func (c *fakeConnection) SetIdleTimeout(time.Duration)       {}

type fakeDialer struct {
	conn httpstream.Connection
}

func (d *fakeDialer) Dial(protocols ...string) (httpstream.Connection, string, error) {
	return d.conn, portforward.PortForwardProtocolV1Name, nil
}

// newStartedPortForward builds a portForward around a real
// portforward.PortForwarder driven by a fake connection, starts forwarding and
// waits until the local listeners are actually bound.
func newStartedPortForward(t *testing.T, remotePort string) *portForward {
	t.Helper()

	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)

	forwarder, err := portforward.NewOnAddresses(
		&fakeDialer{conn: newFakeConnection()},
		[]string{"localhost"},
		[]string{fmt.Sprintf("%s:%s", getPortForwardingPort(), remotePort)},
		stopChan, readyChan, out, errOut,
	)
	require.NoError(t, err)

	p := &portForward{
		PortForwarder: forwarder,
		localPort:     getPortForwardingPort(),
		stopChan:      stopChan,
		readyChan:     readyChan,
		errChan:       make(chan error, 1),
		out:           out,
		errOut:        errOut,
	}

	go func() { p.errChan <- p.ForwardPorts() }()
	t.Cleanup(p.StopPortForwarder)

	select {
	case <-p.Ready:
	case err := <-p.errChan:
		t.Fatalf("port-forward exited before becoming ready: %v (%s)", err, errOut.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for port-forward readiness")
	}

	return p
}

// With DEFAULT_PORT_FORWARDER_PORT=0 the kernel picks the port, so the reported
// address has to be the bound one. Returning the requested "0" means the
// operator scan POSTs to localhost:0 and fails.
func Test_GetPortForwardLocalhost_ReportsBoundPortForEphemeralRequest(t *testing.T) {
	t.Setenv(DefaultPortForwardPortEnv, "0")

	p := newStartedPortForward(t, "5000")

	ports, err := p.GetPorts()
	require.NoError(t, err)
	require.Len(t, ports, 1)
	require.NotZero(t, ports[0].Local, "client-go should have bound a real ephemeral port")

	got := p.GetPortForwardLocalhost()

	assert.NotEqual(t, "localhost:0", got, "must not report the requested port 0 as the address")
	assert.Equal(t, fmt.Sprintf("localhost:%d", ports[0].Local), got)

	// The reported address must be dialable.
	_, portStr, found := strings.Cut(got, ":")
	require.True(t, found)
	parsed, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	assert.NotZero(t, parsed)
}

// The address is fixed once the listeners are bound; mutating the environment
// afterwards must not change what callers are told to dial.
func Test_GetPortForwardLocalhost_IgnoresEnvMutationAfterBinding(t *testing.T) {
	t.Setenv(DefaultPortForwardPortEnv, "0")
	p := newStartedPortForward(t, "5000")

	ports, err := p.GetPorts()
	require.NoError(t, err)
	require.Len(t, ports, 1)

	// Mutating the env after construction must not change the reported address.
	t.Setenv(DefaultPortForwardPortEnv, "9999")

	assert.Equal(t, fmt.Sprintf("localhost:%d", ports[0].Local), p.GetPortForwardLocalhost())
}
