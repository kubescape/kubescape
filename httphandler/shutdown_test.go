package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShutdown_Signals(t *testing.T) {
	if os.Getenv("KS_SHUTDOWN_TEST_CHILD") == "1" {
		err := runWithSignals(func(ctx context.Context) error {
			defer flushOtel(ctx, func(flushCtx context.Context) {
				if flushCtx.Err() != nil {
					panic("cancelled flush context")
				}
				fmt.Println("cleanup complete")
			})
			fmt.Println("ready")
			<-ctx.Done()
			return nil
		})
		if err != nil {
			panic(err)
		}
		return
	}
	for _, signal := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		t.Run(signal.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			executable, err := os.Executable()
			require.NoError(t, err)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestShutdown_Signals$")
			cmd.Env = append(os.Environ(), "KS_SHUTDOWN_TEST_CHILD=1")
			stdout, err := cmd.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, cmd.Start())
			lines := bufio.NewScanner(stdout)
			require.True(t, lines.Scan())
			require.Equal(t, "ready", lines.Text())
			require.NoError(t, cmd.Process.Signal(signal))
			require.True(t, lines.Scan())
			require.Equal(t, "cleanup complete", lines.Text())
			for lines.Scan() {
			}
			require.NoError(t, cmd.Wait())
		})
	}
}

func TestShutdown_ErrorRunsCleanup(t *testing.T) {
	want := errors.New("server failed")
	flushed := false
	err := runWithSignals(func(ctx context.Context) error {
		defer flushOtel(ctx, func(flushCtx context.Context) {
			require.NoError(t, flushCtx.Err())
			deadline, ok := flushCtx.Deadline()
			require.True(t, ok)
			require.WithinDuration(t, time.Now().Add(5*time.Second), deadline, time.Second)
			flushed = true
		})
		return want
	})
	require.ErrorIs(t, err, want)
	require.True(t, flushed)
}
