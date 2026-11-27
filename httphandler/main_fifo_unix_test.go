//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/httphandler/config"
	"golang.org/x/sys/unix"
)

func TestInitializeSaaSEnv_rejectsFIFOWithoutBlocking(t *testing.T) {
	resetSaaSState(t)

	dir := t.TempDir()
	fifo := filepath.Join(dir, "services.json")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", fifo)

	done := make(chan struct{})
	go func() {
		initializeSaaSEnv()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("initializeSaaSEnv blocked on FIFO service-discovery file")
	}

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected FIFO service-discovery file to be rejected, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}

func TestLoadAndSetCredentials_rejectsFIFOWithoutBlocking(t *testing.T) {
	resetSaaSState(t)

	dir := t.TempDir()
	fifo := filepath.Join(dir, "accessKey")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account"), []byte("acct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KS_CREDENTIALS_SECRET_PATH", dir)
	t.Setenv("ACCOUNT_ID", "fallback-account")

	done := make(chan struct{})
	go func() {
		loadAndSetCredentials()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("loadAndSetCredentials blocked on FIFO credential file")
	}

	if got := config.GetAccessKey(); got != "" {
		t.Fatalf("expected empty accessKey when FIFO rejected, got %q", got)
	}
	if got := config.GetAccount(); got != "fallback-account" {
		t.Fatalf("expected fallback-account, got %q", got)
	}
}
