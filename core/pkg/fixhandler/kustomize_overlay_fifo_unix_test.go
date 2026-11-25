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

func TestPlanOverlayChanges_FIFOPatchIsRejectedPromptly(t *testing.T) {
	overlayDir := filepath.Join(t.TempDir(), "overlays", "prod")
	patchesDir := filepath.Join(overlayDir, "patches")
	require.NoError(t, os.MkdirAll(patchesDir, 0o755))

	kustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kustPath, []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n"), 0o600))

	fix := makeOverlayDeploymentFix(overlayDir, kustPath, "my-app")
	patchName := overlayPatchFileName(fix.Resource, kustomizeTarget{Kind: "Deployment", Name: "my-app"})
	fifo := filepath.Join(patchesDir, patchName)
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := planOverlayChanges(overlayDir, []ResourceFixInfo{fix})
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("planOverlayChanges blocked on a FIFO patch file with no writer")
	}
}
