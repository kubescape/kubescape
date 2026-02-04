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

	// Capture interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Handle interrupt signal
	go func() {
		<-ctx.Done()
		// Perform cleanup or graceful shutdown here
		logger.L().StopError("Received interrupt signal, exiting...")
		// Clear the signal handler so that a second interrupt signal shuts down immediately
		stop()
	}()

	if err := cmd.Execute(ctx, version, commit, date); err != nil {
		stop()
		logger.L().Fatal(err.Error())
	}
}