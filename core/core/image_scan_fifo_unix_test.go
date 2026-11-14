//go:build unix && !aix && !illumos && !solaris

package core

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so the call runs under a
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestGetImageExceptionsFromFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "exceptions.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := GetImageExceptionsFromFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrImageExceptionsNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("GetImageExceptionsFromFile blocked on a FIFO with no writer")
	}
}

func TestIsRawSBOMInput_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "sbom.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan bool, 1)
	go func() {
		done <- isRawSBOMInput(fifo)
	}()

	select {
	case res := <-done:
		assert.False(t, res)
	case <-time.After(5 * time.Second):
		t.Fatal("isRawSBOMInput blocked on a FIFO with no writer")
	}
}

func TestOpenLocalRegularFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "test.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		f, err := openLocalRegularFile(fifo)
		if f != nil {
			_ = f.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrImageInputNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("openLocalRegularFile blocked on a FIFO with no writer")
	}
}

func TestWalkTarEntries_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "archive.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan bool, 1)
	go func() {
		_, ok := walkTarEntries(fifo)
		done <- ok
	}()

	select {
	case ok := <-done:
		assert.False(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("walkTarEntries blocked on a FIFO with no writer")
	}
}

func TestScanImageJobs_FIFOWithoutExceptionsIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "archive.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	mockSvc := newMockImageScanService(0)
	results := &resultshandling.ResultsHandler{}
	jobs := []ImageScanJob{
		{Image: "docker-archive:" + fifo},
	}

	done := make(chan error, 1)
	go func() {
		err := scanImageJobs(context.Background(), mockSvc, 1, jobs, results)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrImageInputNotRegular)
		assert.Equal(t, 0, mockSvc.scanCalls, "scanner should not be dispatched for FIFO input")
	case <-time.After(5 * time.Second):
		t.Fatal("scanImageJobs blocked on a FIFO input with no writer")
	}
}

func TestBuildImageScanJobs_FIFOWithoutExceptionsSetsInputErr(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "archive.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	info := &ksmetav1.ImageScanInfo{
		Images: []string{"docker-archive:" + fifo},
	}
	jobs := buildImageScanJobs(info, &cautils.ScanInfo{}, nil)
	require.Len(t, jobs, 1)
	assert.ErrorIs(t, jobs[0].InputErr, ErrImageInputNotRegular)
}

func TestScanWithRegistryMapping_FIFOWithoutExceptionsIsRejected(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "archive.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	mockSvc := newMockImageScanService(0)
	done := make(chan error, 1)
	go func() {
		_, err := scanWithRegistryMapping(
			context.Background(),
			mockSvc,
			"docker-archive:"+fifo,
			nil,
			nil,
			nil,
			nil,
			"",
		)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrImageInputNotRegular)
		assert.Equal(t, 0, mockSvc.scanCalls, "scanner should not be called for FIFO input")
	case <-time.After(5 * time.Second):
		t.Fatal("scanWithRegistryMapping blocked on a FIFO input with no writer")
	}
}
