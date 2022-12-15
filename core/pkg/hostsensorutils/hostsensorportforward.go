package hostsensorutils

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/runtime"
)

// TODO move to API machinery and re-unify with kubelet/server/portfoward
// The subprotocol "portforward.k8s.io" is used for port forwarding.
const PortForwardProtocolV1Name1 = "portforward.k8s.io"

// PortForwarder knows how to listen for local connections and forward them to
// a remote pod via an upgraded HTTP request.
type PortForwarder struct {
	// addresses []listenAddress
	port     ForwardedPort
	stopChan <-chan struct{}

	dialer     httpstream.Dialer
	streamConn httpstream.Connection
	// listeners     []io.Closer
	Ready         chan struct{}
	requestIDLock sync.Mutex
	requestID     int
	out           io.Writer
	errOut        io.Writer
}

// ForwardedPort contains a Local:Remote port pairing.
type ForwardedPort struct {
	ReadyPort chan bool
	Local     *strings.Builder
	Remote    int
}

// ======================

// ForwardPorts formats and executes a port forwarding request. The connection will remain
// open until stopChan is closed.
func (pf *PortForwarder) ForwardPorts() error {
	// defer pf.Close()

	var err error
	pf.streamConn, _, err = pf.dialer.Dial(PortForwardProtocolV1Name)
	if err != nil {
		return fmt.Errorf("error upgrading connection: %s", err)
	}
	defer pf.streamConn.Close()

	return pf.forward()
}

// forward dials the remote host specific in req, upgrades the request, starts
// listeners for each port specified in ports, and forwards local connections
// to the remote host via streams.
func (pf *PortForwarder) forward() error {
	var err error

	listenSuccess := false
	port := &pf.port
	err = pf.listenOnPortAndAddress(port)
	switch {
	case err == nil:
		listenSuccess = true
	default:
		if pf.errOut != nil {
			fmt.Fprintf(pf.errOut, "Unable to listen on port %d: %v\n", port.Local, err)
		}
	}

	if !listenSuccess {
		return fmt.Errorf("Unable to listen on any of the requested ports: %v", pf.port)
	}

	if pf.Ready != nil {
		close(pf.Ready)
	}

	// wait for interrupt or conn closure
	// select {
	// case <-pf.stopChan:
	// case <-pf.streamConn.CloseChan():
	// 	runtime.HandleError(errors.New("lost connection to pod"))
	// }

	return nil
}

// listenOnPort delegates listener creation and waits for connections on requested bind addresses.
// An error is raised based on address groups (default and localhost) and their failure modes
// func (pf *PortForwarder) listenOnPort(port *ForwardedPort) error {
// 	var errors []error
// 	failCounters := make(map[string]int, 2)
// 	successCounters := make(map[string]int, 2)
// 	for _, addr := range pf.addresses {
// 		err := pf.listenOnPortAndAddress(port, addr.protocol, addr.address)
// 		if err != nil {
// 			errors = append(errors, err)
// 			failCounters[addr.failureMode]++
// 		} else {
// 			successCounters[addr.failureMode]++
// 		}
// 	}
// 	if successCounters["all"] == 0 && failCounters["all"] > 0 {
// 		return fmt.Errorf("%s: %v", "Listeners failed to create with the following errors", errors)
// 	}
// 	if failCounters["any"] > 0 {
// 		return fmt.Errorf("%s: %v", "Listeners failed to create with the following errors", errors)
// 	}
// 	return nil
// }

// listenOnPortAndAddress delegates listener creation and waits for new connections
// in the background f
func (pf *PortForwarder) listenOnPortAndAddress(port *ForwardedPort) error {
	// listener, err := pf.getListener(protocol, address, port)
	// if err != nil {
	// 	return err
	// }
	// pf.listeners = append(pf.listeners, listener)
	go pf.waitForConnection(port.Local, *port)
	return nil
}

// // getListener creates a listener on the interface targeted by the given hostname on the given port with
// // the given protocol. protocol is in net.Listen style which basically admits values like tcp, tcp4, tcp6
// func (pf *PortForwarder) getListener(protocol string, hostname string, port *ForwardedPort) (net.Listener, error) {
// 	listener, err := net.Listen(protocol, net.JoinHostPort(hostname, strconv.Itoa(int(port.Local))))
// 	if err != nil {
// 		return nil, fmt.Errorf("Unable to create listener: Error %s", err)
// 	}
// 	listenerAddress := listener.Addr().String()
// 	host, localPort, _ := net.SplitHostPort(listenerAddress)
// 	localPortUInt, err := strconv.ParseUint(localPort, 10, 16)

// 	if err != nil {
// 		fmt.Fprintf(pf.out, "Failed to forward from %s:%d -> %d\n", hostname, localPortUInt, port.Remote)
// 		return nil, fmt.Errorf("Error parsing local port: %s from %s (%s)", err, listenerAddress, host)
// 	}
// 	port.Local = uint16(localPortUInt)
// 	if pf.out != nil {
// 		fmt.Fprintf(pf.out, "Forwarding from %s -> %d\n", net.JoinHostPort(hostname, strconv.Itoa(int(localPortUInt))), port.Remote)
// 	}

// 	return listener, nil
// }

// waitForConnection waits for new connections to listener and handles them in
// the background.
func (pf *PortForwarder) waitForConnection(conn *strings.Builder, port ForwardedPort) {
	for {

		// wait on port Ready channel
		<-pf.port.ReadyPort

		// conn, err := listener.Accept()
		var err error
		if err != nil {
			// TODO consider using something like https://github.com/hydrogen18/stoppableListener?
			if !strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") {
				runtime.HandleError(fmt.Errorf("Error accepting connection on port %d: %v", port.Local, err))
			}
			return
		}
		go pf.handleConnection(conn, port)
	}
}

func (pf *PortForwarder) nextRequestID() int {
	pf.requestIDLock.Lock()
	defer pf.requestIDLock.Unlock()
	id := pf.requestID
	pf.requestID++
	return id
}

// handleConnection copies data between the local connection and the stream to
// the remote server.
func (pf *PortForwarder) handleConnection(conn *strings.Builder, port ForwardedPort) {
	// defer conn.Close()

	if pf.out != nil {
		fmt.Fprintf(pf.out, "Handling connection for %d\n", port.Local)
	}

	requestID := pf.nextRequestID()

	// create error stream
	headers := http.Header{}
	headers.Set(v1.StreamType, v1.StreamTypeError)
	headers.Set(v1.PortHeader, fmt.Sprintf("%d", port.Remote))
	headers.Set(v1.PortForwardRequestIDHeader, strconv.Itoa(requestID))
	errorStream, err := pf.streamConn.CreateStream(headers)
	if err != nil {
		runtime.HandleError(fmt.Errorf("error creating error stream for port %d -> %d: %v", port.Local, port.Remote, err))
		return
	}
	// we're not writing to this stream
	if errorStream != nil {
		errorStream.Close()
	}

	errorChan := make(chan error)
	go func() {
		if errorStream != nil {
			message, err := ioutil.ReadAll(errorStream)
			switch {
			case err != nil:
				errorChan <- fmt.Errorf("error reading from error stream for port %d -> %d: %v", port.Local, port.Remote, err)
			case len(message) > 0:
				errorChan <- fmt.Errorf("an error occurred forwarding %d -> %d: %v", port.Local, port.Remote, string(message))
			}
			close(errorChan)
		}
	}()

	// create data stream
	headers.Set(v1.StreamType, v1.StreamTypeData)
	dataStream, err := pf.streamConn.CreateStream(headers)
	if err != nil {
		runtime.HandleError(fmt.Errorf("error creating forwarding stream for port %d -> %d: %v", port.Local, port.Remote, err))
		return
	}

	localError := make(chan struct{})
	remoteDone := make(chan struct{})

	go func() {
		// Copy from the remote side to the local port.
		if data, err := io.Copy(conn, dataStream); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			runtime.HandleError(fmt.Errorf("error copying from remote stream to local connection: %v", err))
		} else {
			fmt.Print(data)
		}

		// inform the select below that the remote copy is done
		close(remoteDone)
	}()

	go func() {
		// inform server we're not sending any more data after copy unblocks
		defer dataStream.Close()

		// Copy from the local port to the remote side.
		if data, err := io.Copy(dataStream, strings.NewReader(conn.String())); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			runtime.HandleError(fmt.Errorf("error copying from local connection to remote stream: %v", err))
			// break out of the select below without waiting for the other copy to finish
			close(localError)
		} else {
			fmt.Print(data)
		}
	}()

	// wait for either a local->remote error or for copying from remote->local to finish
	select {
	case <-remoteDone:
	case <-localError:
	}

	// always expect something on errorChan (it may be nil)
	err = <-errorChan
	if err != nil {
		runtime.HandleError(err)
	}
}

// func (pf *PortForwarder) Close() {
// 	// stop all listeners
// 	for _, l := range pf.listeners {
// 		if err := l.Close(); err != nil {
// 			runtime.HandleError(fmt.Errorf("error closing listener: %v", err))
// 		}
// 	}
// }
