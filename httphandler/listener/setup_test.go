package listener

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

		err := SetupHTTPListener()
		require.Error(t, err)
		require.Contains(t, err.Error(), "KS_CERT_FILE and KS_KEY_FILE")
	})

	t.Run("fails fast over plain HTTP when the port is already bound", func(t *testing.T) {
		occupied, port := occupyPort(t)
		defer occupied.Close()

		t.Setenv("KS_CERT_FILE", "")
		t.Setenv("KS_KEY_FILE", "")
		t.Setenv("KS_PORT", port)

		err := SetupHTTPListener()
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

		err := SetupHTTPListener()
		// The specific errno isn't portable (syscall.EADDRINUSE doesn't map
		// to Windows' WSAEADDRINUSE); the point of this test is that
		// SetupHTTPListener propagates the ListenAndServe(TLS) error instead
		// of blocking, so a plain error check is enough.
		require.Error(t, err)
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

// TestServePprof_RegistersOwnMuxNotDefaultServeMux guards against a
// regression back to http.ListenAndServe(addr, nil): serving off
// http.DefaultServeMux means these endpoints only exist because some
// unrelated package blank-imports net/http/pprof. If that import were
// removed as dead code, servePprof would keep logging success while every
// request 404s. Registering on a dedicated mux makes the dependency
// self-contained and keeps profiling handlers off the global
// DefaultServeMux.
func TestServePprof_RegistersOwnMuxNotDefaultServeMux(t *testing.T) {
	t.Setenv("KS_PPROF_ENABLED", "true")
	port := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		_, p, err := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, err)
		return p
	}()
	addr := "127.0.0.1:" + port
	t.Setenv("KS_PPROF_ADDR", addr)

	servePprof()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/debug/pprof/")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, time.Second, 10*time.Millisecond, "pprof server did not come up serving its own mux")
}
