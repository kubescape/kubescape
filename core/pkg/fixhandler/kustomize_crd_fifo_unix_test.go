//go:build unix && !aix && !illumos && !solaris

package fixhandler

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCRDsFromChartDir_FIFOWithoutWriterDoesNotBlock(t *testing.T) {
	chartDir := t.TempDir()
	crdsDir := filepath.Join(chartDir, "crds")
	require.NoError(t, os.MkdirAll(crdsDir, 0o755))

	validCRD := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: Widget
`
	require.NoError(t, os.WriteFile(filepath.Join(crdsDir, "widget.yaml"), []byte(validCRD), 0o600))

	fifo := filepath.Join(crdsDir, "pipe-crd.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan map[crdScopeKey]bool, 1)
	go func() {
		done <- extractCRDsFromChartDir(chartDir, chartDir)
	}()

	select {
	case scopes := <-done:
		assert.True(t, scopes[crdScopeKey{Group: "example.com", Kind: "Widget"}])
	case <-time.After(5 * time.Second):
		t.Fatal("extractCRDsFromChartDir blocked on a FIFO file in crds/")
	}
}
