package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd"
)

func main() {
	// Capture interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Handle interrupt signal
	go func() {
		<-ctx.Done()
		// Perform cleanup or graceful shutdown here
		logger.L().StopError("Received interrupt signal, exiting...")
	}()

	if err := cmd.Execute(ctx); err != nil {
		stop()
		logger.L().Fatal(err.Error())
	}
}
