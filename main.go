package main

import (
	"os"
	"os/signal"
	"syscall"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd"
)

func main() {
	// Capture interrupt signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Handle interrupt signal
	go func() {
		<-signalChan
		// Perform cleanup or graceful shutdown here
		logger.L().StopError("Received interrupt signal, exiting...")

		// Exit the program with proper exit code for SIGINT
		os.Exit(130)
	}()

	if err := cmd.Execute(); err != nil {
		logger.L().Fatal(err.Error())
	}

}
