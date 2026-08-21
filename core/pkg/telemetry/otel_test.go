package telemetry

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestResolveEndpoint(t *testing.T) {
	t.Run("flag takes precedence over env", func(t *testing.T) {
		t.Setenv(EnvEndpoint, "env:4317")
		if got := ResolveEndpoint("flag:4317"); got != "flag:4317" {
			t.Errorf("got %q, want %q", got, "flag:4317")
		}
	})

	t.Run("falls back to env when flag empty", func(t *testing.T) {
		t.Setenv(EnvEndpoint, "env:4317")
		if got := ResolveEndpoint(""); got != "env:4317" {
			t.Errorf("got %q, want %q", got, "env:4317")
		}
	})

	t.Run("empty when neither set", func(t *testing.T) {
		os.Unsetenv(EnvEndpoint)
		if got := ResolveEndpoint(""); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestSetup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// otlpgrpc dials lazily, so New() succeeds even against an endpoint with
	// nothing listening; Setup should still return a usable, non-nil
	// shutdown function and register the providers without panicking.
	shutdown, err := Setup(ctx, "127.0.0.1:0", "test-version")
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Setup returned nil shutdown func")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	// Shutdown against an endpoint with nothing listening may return an
	// error (no collector to flush to); what matters here is that it
	// returns rather than hanging or panicking.
	_ = shutdown(shutdownCtx)
}

func TestNoopShutdown(t *testing.T) {
	if err := noopShutdown(context.Background()); err != nil {
		t.Errorf("noopShutdown returned error: %v", err)
	}
}
