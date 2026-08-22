// Package telemetry wires kubescape's already-instrumented OTel spans
// (otel.Tracer("") calls in core/core/scan.go) and metrics (core/metrics,
// the "otel" printer) to a real OTLP exporter when the user asks for one.
//
// Kubescape already creates spans via the global otel.Tracer("") throughout
// the scan (initialization, policies, resources, opa testing, prioritization)
// and reads counters via otel.GetMeterProvider() in core/metrics. Both calls
// resolve against otel's global no-op provider unless something registers a
// real one. Setup is that "something": it is the only place in the codebase
// that constructs an SDK TracerProvider/MeterProvider, and it only does so
// when an OTLP endpoint was actually requested.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc/credentials"
)

// EnvInsecure is the standard OTel SDK env var for opting into plaintext
// gRPC (see https://opentelemetry.io/docs/specs/otel/protocol/exporter/).
const EnvInsecure = "OTEL_EXPORTER_OTLP_INSECURE"

// resolveInsecure strips an explicit http(s):// scheme from endpoint if
// present and reports whether the connection should be plaintext.
//
// A bare host:port (no scheme) -- the flag's own example, and the #3402
// acceptance criterion `--otel-endpoint localhost:4317` -- defaults to
// insecure so scanning against a local collector with no TLS keeps working
// out of the box; set OTEL_EXPORTER_OTLP_INSECURE=false to require TLS for a
// bare endpoint instead.
func resolveInsecure(endpoint string) (cleanEndpoint string, insecure bool) {
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return strings.TrimPrefix(endpoint, "https://"), false
	case strings.HasPrefix(endpoint, "http://"):
		return strings.TrimPrefix(endpoint, "http://"), true
	}
	if v, ok := os.LookupEnv(EnvInsecure); ok {
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			return endpoint, parsed
		}
	}
	return endpoint, true
}

// EnvEndpoint is the standard OTel SDK env var kubescape falls back to when
// --otel-endpoint is not set.
const EnvEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"

// metricExportInterval controls how often accumulated metrics are pushed to
// the collector. A scan is a single short-lived process, not a long-running
// service, so this is intentionally short relative to typical OTel defaults
// (60s) -- without it, a fast scan could exit and get torn down by Shutdown's
// final flush before a single export round ever fires.
const metricExportInterval = 5 * time.Second

// ShutdownFunc flushes and releases any provider Setup registered. It is
// always safe to call, and always safe to defer unconditionally -- when
// telemetry was never enabled it is a no-op.
type ShutdownFunc func(context.Context) error

func noopShutdown(context.Context) error { return nil }

// ResolveEndpoint returns the OTLP endpoint to use: the explicit
// --otel-endpoint flag value if set, otherwise the standard
// OTEL_EXPORTER_OTLP_ENDPOINT env var. An empty result means OTel export is
// disabled and Setup must not be called.
func ResolveEndpoint(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(EnvEndpoint)
}

// Setup registers global OTel TracerProvider and MeterProvider instances
// that export via OTLP/gRPC to endpoint, so every existing
// otel.Tracer("").Start(...) and otel.Meter(...) call site in kubescape
// starts exporting without any further wiring at the call site.
//
// endpoint must be non-empty (callers should check ResolveEndpoint first).
// The returned ShutdownFunc flushes both providers and must be deferred by
// the caller once the scan (and result printing) has finished.
func Setup(ctx context.Context, endpoint, version string) (ShutdownFunc, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "kubescape"),
			attribute.String("service.version", version),
		),
	)
	if err != nil {
		return noopShutdown, fmt.Errorf("build otel resource: %w", err)
	}

	cleanEndpoint, insecure := resolveInsecure(endpoint)

	traceOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cleanEndpoint)}
	metricOpts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cleanEndpoint)}
	if insecure {
		traceOpts = append(traceOpts, otlptracegrpc.WithInsecure())
		metricOpts = append(metricOpts, otlpmetricgrpc.WithInsecure())
	} else {
		creds := credentials.NewTLS(nil) // nil config: system root CA pool
		traceOpts = append(traceOpts, otlptracegrpc.WithTLSCredentials(creds))
		metricOpts = append(metricOpts, otlpmetricgrpc.WithTLSCredentials(creds))
	}

	traceExporter, err := otlptracegrpc.New(ctx, traceOpts...)
	if err != nil {
		return noopShutdown, fmt.Errorf("create otlp trace exporter for %q: %w", endpoint, err)
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, metricOpts...)
	if err != nil {
		return noopShutdown, fmt.Errorf("create otlp metric exporter for %q: %w", endpoint, err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(metricExportInterval))),
		sdkmetric.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	logger.L().Ctx(ctx).Info("OpenTelemetry export enabled", helpers.String("endpoint", endpoint))

	return func(shutdownCtx context.Context) error {
		return errors.Join(
			tp.Shutdown(shutdownCtx),
			mp.Shutdown(shutdownCtx),
		)
	}, nil
}
