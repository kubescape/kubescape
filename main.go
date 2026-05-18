package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd"
)

// GoReleaser will fill these at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Set the global build number for version checking
	versioncheck.BuildNumber = version

	// Capture interrupt signal on a dedicated channel so the watcher can
	// distinguish a real signal from a normal cancel() on graceful exit.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-sigCh:
			logger.L().StopError("Received interrupt signal, exiting...")
			// Clear the signal handler so a second signal terminates immediately.
			signal.Stop(sigCh)
			cancel()
		case <-ctx.Done():
			// Normal shutdown — no log line.
		}
	}()

	if err := cmd.Execute(ctx, version, commit, date); err != nil {
		cancel()
		logger.L().Fatal(err.Error())
	}
}
