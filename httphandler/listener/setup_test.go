package listener

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
