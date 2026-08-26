package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// A scan is a one-shot command, not a long-lived service, so the exporter
// defaults are the wrong shape: they allow a 10s export timeout and retry a
// failed batch for up to a minute. Against an unreachable collector that turns
// the final flush into a stall the user has to sit through. These bound a
// single export attempt and the total time spent retrying it, and
// shutdownTimeout is the backstop over both signals.
//
// Retries stay enabled so a collector that blips mid-scan still receives the
// batch; they just stop well short of waiting out one that is not there.
const (
	exportTimeout        = 3 * time.Second
	retryInitialInterval = 100 * time.Millisecond
	retryMaxInterval     = 500 * time.Millisecond
	retryMaxElapsedTime  = 2 * time.Second
	shutdownTimeout      = 5 * time.Second
)

// ShutdownFunc flushes buffered spans and metrics and releases the exporters.
// It is safe to call more than once.
type ShutdownFunc func(context.Context) error

var (
	stateMu  sync.Mutex
	isActive bool
)

// Active reports whether Setup installed SDK providers that are still running.
// Scan subcommands can nest (the bare `scan` command delegates to `scan
// framework`), so the lifecycle wrapper uses this to avoid a second setup that
// would replace the running providers mid-scan.
func Active() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	return isActive
}

// Setup installs OTLP-backed tracer and meter providers as the process
// globals. Kubescape already annotates its scan pipeline with otel.Tracer("")
// spans and registers instruments against otel.GetMeterProvider(); until a real
// provider is installed those resolve against the SDK's no-op implementations
// and nothing is recorded. Setup is what makes the existing instrumentation
// observable, so it must run before the scan starts.
//
// Callers must invoke the returned ShutdownFunc, otherwise the last batch of
// spans and the final metric collection are dropped.
func Setup(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	if !cfg.Enabled() {
		return noopShutdown, nil
	}

	stateMu.Lock()
	defer stateMu.Unlock()
	if isActive {
		return noopShutdown, nil
	}

	res, err := newResource(ctx, cfg)
	if err != nil {
		return nil, err
	}

	traceExporter, err := newTraceExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}

	metricExporter, err := newMetricExporter(ctx, cfg)
	if err != nil {
		// The trace exporter owns a live connection at this point; drop it
		// rather than leaking it back to a caller that only sees an error.
		_ = traceExporter.Shutdown(ctx)
		return nil, fmt.Errorf("otlp metric exporter: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)

	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	previousPropagator := otel.GetTextMapPropagator()

	// Export failures are an observability problem, never a scan problem. The
	// default handler writes to stderr and would corrupt machine-readable
	// output written to stdout, so route it through the logger instead.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.L().Debug("opentelemetry exporter error", helpers.Error(err))
	}))
	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Instruments bind to whichever meter provider is current when they are
	// created, so they have to be built after the provider is installed.
	initScanInstruments()

	isActive = true

	var shutdownOnce sync.Once
	return func(shutdownCtx context.Context) error {
		var shutdownErr error
		shutdownOnce.Do(func() {
			// The scan's own context is usually cancelled or past its deadline
			// by the time results are printed; flushing needs a live one.
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(shutdownCtx), shutdownTimeout)
			defer cancel()

			// The two providers hold separate connections, so flushing them
			// concurrently keeps the worst case at one export timeout rather
			// than the sum of both. That is the difference a user feels when
			// the configured collector is not answering.
			var traceErr, metricErr error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				traceErr = tracerProvider.Shutdown(flushCtx)
			}()
			go func() {
				defer wg.Done()
				metricErr = meterProvider.Shutdown(flushCtx)
			}()
			wg.Wait()

			shutdownErr = errors.Join(traceErr, metricErr)

			otel.SetTracerProvider(previousTracerProvider)
			otel.SetMeterProvider(previousMeterProvider)
			otel.SetTextMapPropagator(previousPropagator)
			resetScanInstruments()

			stateMu.Lock()
			isActive = false
			stateMu.Unlock()
		})
		return shutdownErr
	}, nil
}

func noopShutdown(context.Context) error { return nil }

func newResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attributes := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
	}
	if cfg.Version != "" {
		attributes = append(attributes, semconv.ServiceVersion(cfg.Version))
	}

	options := []resource.Option{
		resource.WithProcessRuntimeVersion(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attributes...),
	}
	if !cfg.Redact {
		options = append(options, resource.WithHost())
	}

	res, err := resource.New(ctx, options...)
	// A schema conflict between detectors is recoverable: the partial resource
	// is still usable and is better than refusing to export at all.
	if errors.Is(err, resource.ErrSchemaURLConflict) {
		logger.L().Debug("opentelemetry resource schema conflict", helpers.Error(err))
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("opentelemetry resource: %w", err)
	}
	return res, nil
}

func newTraceExporter(ctx context.Context, cfg Config) (*otlptrace.Exporter, error) {
	if cfg.Protocol == ProtocolHTTP {
		options := []otlptracehttp.Option{
			otlptracehttp.WithTimeout(exportTimeout),
			otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
				Enabled:         true,
				InitialInterval: retryInitialInterval,
				MaxInterval:     retryMaxInterval,
				MaxElapsedTime:  retryMaxElapsedTime,
			}),
		}
		if cfg.Endpoint != "" {
			options = append(options, otlptracehttp.WithEndpoint(cfg.Endpoint))
			if cfg.Insecure {
				options = append(options, otlptracehttp.WithInsecure())
			}
		}
		return otlptracehttp.New(ctx, options...)
	}

	options := []otlptracegrpc.Option{
		otlptracegrpc.WithTimeout(exportTimeout),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: retryInitialInterval,
			MaxInterval:     retryMaxInterval,
			MaxElapsedTime:  retryMaxElapsedTime,
		}),
	}
	if cfg.Endpoint != "" {
		options = append(options, otlptracegrpc.WithEndpoint(cfg.Endpoint))
		if cfg.Insecure {
			options = append(options, otlptracegrpc.WithInsecure())
		}
	}
	return otlptracegrpc.New(ctx, options...)
}

func newMetricExporter(ctx context.Context, cfg Config) (sdkmetric.Exporter, error) {
	if cfg.Protocol == ProtocolHTTP {
		options := []otlpmetrichttp.Option{
			otlpmetrichttp.WithTimeout(exportTimeout),
			otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{
				Enabled:         true,
				InitialInterval: retryInitialInterval,
				MaxInterval:     retryMaxInterval,
				MaxElapsedTime:  retryMaxElapsedTime,
			}),
		}
		if cfg.Endpoint != "" {
			options = append(options, otlpmetrichttp.WithEndpoint(cfg.Endpoint))
			if cfg.Insecure {
				options = append(options, otlpmetrichttp.WithInsecure())
			}
		}
		return otlpmetrichttp.New(ctx, options...)
	}

	options := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithTimeout(exportTimeout),
		otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: retryInitialInterval,
			MaxInterval:     retryMaxInterval,
			MaxElapsedTime:  retryMaxElapsedTime,
		}),
	}
	if cfg.Endpoint != "" {
		options = append(options, otlpmetricgrpc.WithEndpoint(cfg.Endpoint))
		if cfg.Insecure {
			options = append(options, otlpmetricgrpc.WithInsecure())
		}
	}
	return otlpmetricgrpc.New(ctx, options...)
}
