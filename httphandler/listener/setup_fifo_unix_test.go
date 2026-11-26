//go:build unix

package listener

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLoadTLSKey_RejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	_, keyFile := writeTestTLSFiles(t)

	t.Run("direct FIFO cert fails fast", func(t *testing.T) {
		fifo := filepath.Join(dir, "cert-fifo.pem")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))

		done := make(chan error, 1)
		go func() {
			_, err := loadTLSKey(fifo, keyFile)
			done <- err
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, errTLSFileNotRegular)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("loadTLSKey blocked on FIFO")
		}
	})

	t.Run("rotated symlink to FIFO fails fast and preserves active cert", func(t *testing.T) {
		certFile, activeKey := writeTestTLSFiles(t)
		reloader, err := newTLSReloader(certFile, activeKey)
		require.NoError(t, err)

		fifo := filepath.Join(dir, "rotated-fifo.pem")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))
		require.NoError(t, os.Remove(certFile))
		require.NoError(t, os.Symlink(fifo, certFile))

		type result struct {
			cert *tls.Certificate
			err  error
		}
		done := make(chan result, 1)
		go func() {
			cert, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
			done <- result{cert: cert, err: err}
		}()

		select {
		case res := <-done:
			require.NoError(t, res.err)
			require.NotNil(t, res.cert)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("tlsReloader.GetCertificate blocked on rotated FIFO")
		}
	})
}
