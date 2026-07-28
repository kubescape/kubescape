package listener

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/go-logger"
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
		if got := getCertFile(); got != "/tmp/cert.pem" {
			t.Fatalf("getCertFile() = %q, want %q", got, "/tmp/cert.pem")
		}
	})

	t.Run("returns empty when unset", func(t *testing.T) {
		t.Setenv("KS_CERT_FILE", "")
		if got := getCertFile(); got != "" {
			t.Fatalf("getCertFile() = %q, want empty", got)
		}
	})
}

func TestGetKeyFile(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_KEY_FILE", "/tmp/key.pem")
		if got := getKeyFile(); got != "/tmp/key.pem" {
			t.Fatalf("getKeyFile() = %q, want %q", got, "/tmp/key.pem")
		}
	})

	t.Run("returns empty when unset", func(t *testing.T) {
		t.Setenv("KS_KEY_FILE", "")
		if got := getKeyFile(); got != "" {
			t.Fatalf("getKeyFile() = %q, want empty", got)
		}
	})
}

func TestServePprof(t *testing.T) {
	// At the default (non-debug) log level, servePprof must return without
	// actually binding the pprof listener. Deliberately does not touch the
	// logger's level: go-logger's IconLogger stores it in a plain field with
	// no synchronization, so calling SetLevel here would race the level read
	// servePprof's goroutine does internally.
	require.Equal(t, "info", logger.L().GetLevel())

	servePprof()
	// give the goroutine a chance to run before the test (and its coverage
	// counters) exit.
	time.Sleep(20 * time.Millisecond)

	// The regression this guards against: servePprof binding pprof even at
	// info level. If it did, this bind would fail instead of succeeding.
	ln, err := net.Listen("tcp", ":6060")
	require.NoError(t, err, "pprof must not listen when log level is info")
	defer ln.Close()
}

// occupyPort binds a loopback listener on a free port so a subsequent bind to
// ":<port>" (all interfaces) fails immediately with "address already in use",
// letting SetupHTTPListener's server-start path be exercised without actually
// serving traffic.
func occupyPort(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
		require.ErrorIs(t, err, syscall.EADDRINUSE)
	})

	t.Run("fails fast over TLS when the port is already bound", func(t *testing.T) {
		certFile, keyFile := writeTestTLSFiles(t)
		occupied, port := occupyPort(t)
		defer occupied.Close()

		t.Setenv("KS_CERT_FILE", certFile)
		t.Setenv("KS_KEY_FILE", keyFile)
		t.Setenv("KS_PORT", port)

		err := SetupHTTPListener()
		require.ErrorIs(t, err, syscall.EADDRINUSE)
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
