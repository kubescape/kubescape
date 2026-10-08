package listener

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTLSKey(t *testing.T) {
	t.Run("returns error when cert is set without key", func(t *testing.T) {
		pair, err := loadTLSKey("cert.pem", "")
		require.Nil(t, pair)
		require.EqualError(t, err, `both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile="cert.pem", keyFile="")`)
	})

	t.Run("returns error when key is set without cert", func(t *testing.T) {
		pair, err := loadTLSKey("", "key.pem")
		require.Nil(t, pair)
		require.EqualError(t, err, `both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile="", keyFile="key.pem")`)
	})

	t.Run("loads a valid certificate and key pair", func(t *testing.T) {
		certFile, keyFile := writeTestTLSFiles(t)

		pair, err := loadTLSKey(certFile, keyFile)
		require.NoError(t, err)
		require.NotNil(t, pair)
		assert.NotEmpty(t, pair.Certificate)
		assert.NotNil(t, pair.PrivateKey)
	})

	t.Run("returns nil pair and nil error when neither is set", func(t *testing.T) {
		pair, err := loadTLSKey("", "")
		require.NoError(t, err)
		require.Nil(t, pair)
	})

	t.Run("returns error when the cert/key files cannot be loaded", func(t *testing.T) {
		dir := t.TempDir()
		pair, err := loadTLSKey(filepath.Join(dir, "missing-cert.pem"), filepath.Join(dir, "missing-key.pem"))
		require.Error(t, err)
		require.Nil(t, pair)
		require.Contains(t, err.Error(), "failed to load key pair")

		// We expect the error to wrap fs.ErrNotExist because the file is missing.
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestGetCertFile(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_CERT_FILE", "/tmp/cert.pem")
		require.Equal(t, "/tmp/cert.pem", getCertFile())
	})

	t.Run("returns empty when unset", func(t *testing.T) {
		t.Setenv("KS_CERT_FILE", "placeholder") // registers cleanup/restore
		os.Unsetenv("KS_CERT_FILE")
		require.Empty(t, getCertFile())
	})
}

func TestGetKeyFile(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_KEY_FILE", "/tmp/key.pem")
		require.Equal(t, "/tmp/key.pem", getKeyFile())
	})

	t.Run("returns empty when unset", func(t *testing.T) {
		t.Setenv("KS_KEY_FILE", "placeholder") // registers cleanup/restore
		os.Unsetenv("KS_KEY_FILE")
		require.Empty(t, getKeyFile())
	})
}

// occupyPort binds the same wildcard address shape used by SetupHTTPListener
// so a subsequent bind to ":<port>" fails immediately with "address already in
// use", letting the server-start path be exercised without serving traffic.
func occupyPort(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return ln, port
}

func TestSetupHTTPListener(t *testing.T) {
	t.Run("returns error on invalid TLS config", func(t *testing.T) {
		t.Setenv("KS_CERT_FILE", "cert.pem")
		t.Setenv("KS_KEY_FILE", "")

		err := SetupHTTPListener(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "KS_CERT_FILE and KS_KEY_FILE")
	})

	t.Run("fails fast over plain HTTP when the port is already bound", func(t *testing.T) {
		occupied, port := occupyPort(t)
		defer occupied.Close()

		t.Setenv("KS_CERT_FILE", "")
		t.Setenv("KS_KEY_FILE", "")
		t.Setenv("KS_PORT", port)

		err := SetupHTTPListener(context.Background())
		// The specific errno isn't portable (syscall.EADDRINUSE doesn't map
		// to Windows' WSAEADDRINUSE); the point of this test is that
		// SetupHTTPListener propagates the ListenAndServe(TLS) error instead
		// of blocking, so a plain error check is enough.
		require.Error(t, err)
	})

	t.Run("fails fast over TLS when the port is already bound", func(t *testing.T) {
		certFile, keyFile := writeTestTLSFiles(t)
		occupied, port := occupyPort(t)
		defer occupied.Close()

		t.Setenv("KS_CERT_FILE", certFile)
		t.Setenv("KS_KEY_FILE", keyFile)
		t.Setenv("KS_PORT", port)

		err := SetupHTTPListener(context.Background())
		// The specific errno isn't portable (syscall.EADDRINUSE doesn't map
		// to Windows' WSAEADDRINUSE); the point of this test is that
		// SetupHTTPListener propagates the ListenAndServe(TLS) error instead
		// of blocking, so a plain error check is enough.
		require.Error(t, err)
	})

	t.Run("serves over TLS and dynamically picks up rotated certificate", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "cert.pem")
		keyFile := filepath.Join(dir, "key.pem")

		certPEM1, keyPEM1 := generateTestCertAndKey(t, "cert-v1.local")
		require.NoError(t, os.WriteFile(certFile, certPEM1, 0o600))
		require.NoError(t, os.WriteFile(keyFile, keyPEM1, 0o600))

		port := freePort(t)
		t.Setenv("KS_CERT_FILE", certFile)
		t.Setenv("KS_KEY_FILE", keyFile)
		t.Setenv("KS_PORT", port)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverErr := make(chan error, 1)
		go func() {
			serverErr <- SetupHTTPListener(ctx)
		}()

		getPeerCertCN := func() (string, error) {
			conf := &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- test helper to inspect served certificate
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", "127.0.0.1:"+port, conf)
			if err != nil {
				return "", err
			}
			defer conn.Close()
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return "", errors.New("no peer certificates")
			}
			return certs[0].Subject.CommonName, nil
		}

		// Wait until server is up and serving cert-v1
		require.Eventually(t, func() bool {
			cn, err := getPeerCertCN()
			return err == nil && cn == "cert-v1.local"
		}, 3*time.Second, 50*time.Millisecond)

		// Rotate certificate files on disk
		time.Sleep(10 * time.Millisecond)
		certPEM2, keyPEM2 := generateTestCertAndKey(t, "cert-v2.local")
		require.NoError(t, os.WriteFile(certFile, certPEM2, 0o600))
		require.NoError(t, os.WriteFile(keyFile, keyPEM2, 0o600))

		// Subsequent connection should receive rotated certificate without server restart
		require.Eventually(t, func() bool {
			cn, err := getPeerCertCN()
			return err == nil && cn == "cert-v2.local"
		}, 3*time.Second, 50*time.Millisecond)

		cancel()
		require.NoError(t, <-serverErr)
	})
}

func writeTestTLSFiles(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return certFile, keyFile
}

func TestGetPort(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_PORT", "9090")
		if got := getPort(); got != "9090" {
			t.Fatalf("getPort() = %q, want %q", got, "9090")
		}
	})

	t.Run("returns default when unset", func(t *testing.T) {
		t.Setenv("KS_PORT", "")
		if got := getPort(); got != "8080" {
			t.Fatalf("getPort() = %q, want %q", got, "8080")
		}
	})
}

func TestGetOffline(t *testing.T) {
	t.Run("returns true only for literal true", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "true")
		if !getOffline() {
			t.Fatal("getOffline() = false, want true")
		}
	})

	t.Run("returns false when unset", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "")
		if getOffline() {
			t.Fatal("getOffline() = true, want false")
		}
	})

	t.Run("returns false for other values", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "TRUE")
		if getOffline() {
			t.Fatal("getOffline() = true, want false")
		}
	})
}

func TestGetPprofEnabled(t *testing.T) {
	t.Run("returns false when unset", func(t *testing.T) {
		t.Setenv("KS_PPROF_ENABLED", "")
		if getPprofEnabled() {
			t.Fatal("getPprofEnabled() = true, want false")
		}
	})

	t.Run("returns true for lowercase true", func(t *testing.T) {
		t.Setenv("KS_PPROF_ENABLED", "true")
		if !getPprofEnabled() {
			t.Fatal("getPprofEnabled() = false, want true")
		}
	})

	t.Run("returns true case-insensitively", func(t *testing.T) {
		t.Setenv("KS_PPROF_ENABLED", "TRUE")
		if !getPprofEnabled() {
			t.Fatal("getPprofEnabled() = false, want true — this is a security-relevant knob an operator sets by hand, so it must not silently no-op on a differently-cased value")
		}
	})

	t.Run("returns false for other values", func(t *testing.T) {
		t.Setenv("KS_PPROF_ENABLED", "1")
		if getPprofEnabled() {
			t.Fatal("getPprofEnabled() = true, want false")
		}
	})
}

func TestGetPprofAddr(t *testing.T) {
	t.Run("returns default when unset", func(t *testing.T) {
		t.Setenv("KS_PPROF_ADDR", "")
		if got := getPprofAddr(); got != "127.0.0.1:6060" {
			t.Fatalf("getPprofAddr() = %q, want %q", got, "127.0.0.1:6060")
		}
	})

	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_PPROF_ADDR", "127.0.0.1:7070")
		if got := getPprofAddr(); got != "127.0.0.1:7070" {
			t.Fatalf("getPprofAddr() = %q, want %q", got, "127.0.0.1:7070")
		}
	})
}

// TestNewPprofServer_UsesItsOwnMux guards against a regression back to
// http.ListenAndServe(addr, nil) / Handler: nil: a nil Handler falls back to
// http.DefaultServeMux, which - because net/http/pprof is imported - also
// answers /debug/pprof/ with 200. A live HTTP probe against the listening
// server can't tell the two muxes apart, so this asserts on the handler
// itself instead.
func TestNewPprofServer_UsesItsOwnMux(t *testing.T) {
	srv := newPprofServer("127.0.0.1:0")

	require.NotNil(t, srv.Handler)
	require.NotSame(t, http.DefaultServeMux, srv.Handler)

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestServePprof_ListensWhenEnabled proves servePprof actually binds and
// serves when KS_PPROF_ENABLED=true.
func TestServePprof_ListensWhenEnabled(t *testing.T) {
	t.Setenv("KS_PPROF_ENABLED", "true")
	addr := "127.0.0.1:" + freePort(t)
	t.Setenv("KS_PPROF_ADDR", addr)

	servePprof()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, time.Second, 10*time.Millisecond, "pprof server did not come up")
}

// TestServePprof_DoesNotListenWhenDisabled is the negative case: the
// security property this feature exists to establish is that pprof stays
// off unless explicitly opted into.
func TestServePprof_DoesNotListenWhenDisabled(t *testing.T) {
	t.Setenv("KS_PPROF_ENABLED", "")
	addr := "127.0.0.1:" + freePort(t)
	t.Setenv("KS_PPROF_ADDR", addr)

	servePprof()

	require.Never(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 250*time.Millisecond, 25*time.Millisecond, "pprof server must not listen when KS_PPROF_ENABLED is unset")
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	_, p, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return p
}

func generateTestCertAndKey(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM
}

func TestNewTLSReloader(t *testing.T) {
	t.Run("returns nil reloader and nil error when both are unset", func(t *testing.T) {
		reloader, err := newTLSReloader("", "")
		require.NoError(t, err)
		require.Nil(t, reloader)
	})

	t.Run("returns error when cert is set without key", func(t *testing.T) {
		reloader, err := newTLSReloader("cert.pem", "")
		require.Nil(t, reloader)
		require.EqualError(t, err, `both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile="cert.pem", keyFile="")`)
	})

	t.Run("returns error when key is set without cert", func(t *testing.T) {
		reloader, err := newTLSReloader("", "key.pem")
		require.Nil(t, reloader)
		require.EqualError(t, err, `both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile="", keyFile="key.pem")`)
	})

	t.Run("returns error when files do not exist", func(t *testing.T) {
		dir := t.TempDir()
		reloader, err := newTLSReloader(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
		require.Error(t, err)
		require.Nil(t, reloader)
		require.Contains(t, err.Error(), "failed to stat cert file")
	})

	t.Run("initializes reloader successfully with valid files", func(t *testing.T) {
		certFile, keyFile := writeTestTLSFiles(t)
		reloader, err := newTLSReloader(certFile, keyFile)
		require.NoError(t, err)
		require.NotNil(t, reloader)

		cert, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
	})
}

func TestTLSReloader_DynamicReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	certPEM1, keyPEM1 := generateTestCertAndKey(t, "initial.example.com")
	require.NoError(t, os.WriteFile(certFile, certPEM1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM1, 0o600))

	reloader, err := newTLSReloader(certFile, keyFile)
	require.NoError(t, err)
	require.NotNil(t, reloader)

	// Verify initial certificate
	cert1, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "initial.example.com", parsed1.Subject.CommonName)

	// Sleep briefly to ensure filesystem mtime difference
	time.Sleep(10 * time.Millisecond)

	// Update files with new certificate
	certPEM2, keyPEM2 := generateTestCertAndKey(t, "rotated.example.com")
	require.NoError(t, os.WriteFile(certFile, certPEM2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM2, 0o600))

	// GetCertificate should detect change and reload
	cert2, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed2, err := x509.ParseCertificate(cert2.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "rotated.example.com", parsed2.Subject.CommonName)
}

func TestTLSReloader_FallbackOnInvalidRotatedFile(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	certPEM, keyPEM := generateTestCertAndKey(t, "stable.example.com")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	reloader, err := newTLSReloader(certFile, keyFile)
	require.NoError(t, err)

	cert1, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "stable.example.com", parsed1.Subject.CommonName)

	time.Sleep(10 * time.Millisecond)

	// Corrupt the cert file to simulate an in-progress or broken write
	require.NoError(t, os.WriteFile(certFile, []byte("invalid-cert-bytes"), 0o600))

	// Should not fail the handshake; should fallback to last valid certificate
	cert2, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed2, err := x509.ParseCertificate(cert2.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "stable.example.com", parsed2.Subject.CommonName)
}

func TestTLSReloader_SymlinkRotation(t *testing.T) {
	// Simulates Kubernetes Secret volume mount symlink swaps:
	// tls.crt -> ..data/tls.crt
	// ..data -> ..dir1 (initially)
	// ..data -> ..dir2 (after rotation)
	rootDir := t.TempDir()
	dir1 := filepath.Join(rootDir, "dir1")
	dir2 := filepath.Join(rootDir, "dir2")
	require.NoError(t, os.Mkdir(dir1, 0o700))
	require.NoError(t, os.Mkdir(dir2, 0o700))

	certPEM1, keyPEM1 := generateTestCertAndKey(t, "k8s-cert-1.example.com")
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "tls.crt"), certPEM1, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "tls.key"), keyPEM1, 0o600))

	certPEM2, keyPEM2 := generateTestCertAndKey(t, "k8s-cert-2.example.com")
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "tls.crt"), certPEM2, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "tls.key"), keyPEM2, 0o600))

	dataSymlink := filepath.Join(rootDir, "..data")
	require.NoError(t, os.Symlink(dir1, dataSymlink))

	certSymlink := filepath.Join(rootDir, "tls.crt")
	keySymlink := filepath.Join(rootDir, "tls.key")
	require.NoError(t, os.Symlink(filepath.Join(dataSymlink, "tls.crt"), certSymlink))
	require.NoError(t, os.Symlink(filepath.Join(dataSymlink, "tls.key"), keySymlink))

	reloader, err := newTLSReloader(certSymlink, keySymlink)
	require.NoError(t, err)

	cert1, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "k8s-cert-1.example.com", parsed1.Subject.CommonName)

	time.Sleep(10 * time.Millisecond)

	// Atomically swap ..data symlink
	tmpDataSymlink := filepath.Join(rootDir, "..data_tmp")
	require.NoError(t, os.Symlink(dir2, tmpDataSymlink))
	require.NoError(t, os.Rename(tmpDataSymlink, dataSymlink))

	// Reloader should follow symlink to dir2 and reload
	cert2, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	parsed2, err := x509.ParseCertificate(cert2.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "k8s-cert-2.example.com", parsed2.Subject.CommonName)
}

func TestTLSReloader_ConcurrentGetCertificate(t *testing.T) {
	certFile, keyFile := writeTestTLSFiles(t)
	reloader, err := newTLSReloader(certFile, keyFile)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cert, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		}()
	}
	wg.Wait()
}
