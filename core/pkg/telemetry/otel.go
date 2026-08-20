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
)

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

	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return noopShutdown, fmt.Errorf("create otlp trace exporter for %q: %w", endpoint, err)
	}

	metricExporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(endpoint),
		otlpmetricgrpc.WithInsecure(),
	)
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
