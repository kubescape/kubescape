package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	v1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"github.com/stretchr/testify/require"
)

func TestShutdown_HTTPAndTLS(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "HTTP"
		if encrypted {
			name = "TLS"
		}
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			h := v1.NewHTTPHandler(false)
			started, release := make(chan struct{}), make(chan struct{})
			server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
				w.WriteHeader(http.StatusNoContent)
			})}
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			scheme := "http"
			if encrypted {
				cert, key := writeTestTLSFiles(t)
				pair, err := loadTLSKey(cert, key)
				require.NoError(t, err)
				server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*pair}}
				certificate, err := x509.ParseCertificate(pair.Certificate[0])
				require.NoError(t, err)
				roots := x509.NewCertPool()
				roots.AddCert(certificate)
				transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
				scheme = "https"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- serveUntilShutdown(ctx, server, ln, h, time.Second, 3*time.Second) }()
			response := make(chan error, 1)
			go func() {
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				resp, err := client.Get(scheme + "://" + ln.Addr().String())
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode != http.StatusNoContent {
						err = errors.New("request did not finish normally")
					}
				}
				response <- err
			}()
			<-started
			cancel()
			close(release)
			require.NoError(t, <-response)
			require.NoError(t, <-done)
			conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err, "listener must be closed before shutdown returns")
		})
	}
}

func TestShutdown_IdleAndAlreadyCancelled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := &http.Server{ReadHeaderTimeout: time.Second}
	require.NoError(t, serveUntilShutdown(ctx, server, ln, v1.NewHTTPHandler(false), time.Second, time.Second))
}

type failingListener struct {
	net.Listener
	err error
}

func (l failingListener) Accept() (net.Conn, error) { return nil, l.err }

func TestShutdown_PreservesServeFailure(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "serve failure", true: "racing cancellation"}[cancelled], func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			want := errors.New("accept failed")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Cancel in Serve's deferred listener close, after Serve has selected
			// its error. Both cancellation and the genuine serve error can then
			// reach the coordinator together.
			listener := &cancelOnCloseListener{Listener: failingListener{ln, want}}
			if cancelled {
				listener.cancel = cancel
			}
			server := &http.Server{ReadHeaderTimeout: time.Second}
			require.ErrorIs(t, serveUntilShutdown(ctx, server, listener, v1.NewHTTPHandler(false), time.Second, time.Second), want)
		})
	}
}

type cancelOnCloseListener struct {
	net.Listener
	cancel context.CancelFunc
}

func (l *cancelOnCloseListener) Close() error {
	err := l.Listener.Close()
	if l.cancel != nil {
		l.cancel()
	}
	return err
}

func TestShutdown_HTTPDeadlineClosesActiveRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	started, finished := make(chan struct{}), make(chan struct{})
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finished)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveUntilShutdown(ctx, server, ln, v1.NewHTTPHandler(false), 0, 10*time.Millisecond) }()
	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String())
		if resp != nil {
			resp.Body.Close()
		}
		requestDone <- err
	}()
	<-started
	cancel()
	require.ErrorIs(t, <-done, context.DeadlineExceeded)
	<-finished
	require.Error(t, <-requestDone)
}
