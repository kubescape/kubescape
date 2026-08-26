package scan

import (
	"context"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// rootSpanName is the parent of the phase spans Kubescape already emits
// (initialization, policies, resources, opa testing, reporting).
const (
	rootSpanName = "kubescape.scan"

	commandAttribute    = "kubescape.command"
	scanTargetAttribute = "kubescape.scan.target"
)

// telemetryExemptCommands lists subcommands that do not run a scan and so have
// nothing to export.
var telemetryExemptCommands = map[string]bool{
	"validate-contract": true,
}

// installTelemetry wraps the RunE of the scan command and every subcommand
// registered under it, so a subcommand added later inherits the lifecycle
// without a second wiring step. The wrapper is what turns the pipeline's
// existing spans and instruments into exported telemetry; without it they
// resolve against the SDK's no-op providers.
func installTelemetry(cmd *cobra.Command, ks meta.IKubescape, scanInfo *cautils.ScanInfo) {
	if telemetryExemptCommands[cmd.Name()] {
		return
	}
	if cmd.RunE != nil {
		cmd.RunE = wrapWithTelemetry(cmd.RunE, ks, scanInfo)
	}
	for _, sub := range cmd.Commands() {
		installTelemetry(sub, ks, scanInfo)
	}
}

func wrapWithTelemetry(run func(*cobra.Command, []string) error, ks meta.IKubescape, scanInfo *cautils.ScanInfo) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) (runErr error) {
		// The bare `scan` command delegates to the framework scan, so a wrapped
		// command can invoke another. Only the outermost one owns the lifecycle.
		if telemetry.Active() {
			return run(cmd, args)
		}

		cfg, err := telemetry.ResolveConfig(scanInfo.OtelEndpoint, versioncheck.BuildNumber)
		if err != nil {
			return err
		}
		// A run that anonymizes or encrypts its report must not describe the
		// same things to a collector in the clear.
		cfg.Redact = scanInfo.Hide || scanInfo.EncryptionEnabled
		if !cfg.Enabled() {
			return run(cmd, args)
		}

		shutdown, err := telemetry.Setup(cmd.Context(), cfg)
		if err != nil {
			// An unreachable collector is an observability failure, not a scan
			// failure: the scan still has to produce its report and exit code.
			logger.L().Warning("failed to enable OpenTelemetry export, continuing without it", helpers.Error(err))
			return run(cmd, args)
		}

		previousCtx := ks.Context()
		ctx, span := otel.Tracer(telemetry.TracerName).Start(previousCtx, rootSpanName,
			trace.WithAttributes(attribute.String(commandAttribute, cmd.CommandPath())),
		)
		// The pipeline reads its context from ks, so the root span has to be
		// published there for the phase spans to attach to it.
		ks.SetContext(ctx)

		// Deferred so the trace is closed and flushed however the scan ends:
		// a threshold failure, an error, or a panic on its way up.
		start := time.Now()
		defer func() {
			elapsed := time.Since(start)

			if runErr != nil {
				span.RecordError(runErr)
				span.SetStatus(codes.Error, runErr.Error())
			}
			span.SetAttributes(attribute.String(scanTargetAttribute, string(scanInfo.ScanType)))
			span.End()

			telemetry.RecordScan(ctx, telemetry.ScanOutcome{
				Target:   string(scanInfo.ScanType),
				Duration: elapsed,
			})

			ks.SetContext(previousCtx)
			flushTelemetry(previousCtx, shutdown)
		}()

		return run(cmd, args)
	}
}

// flushTelemetry always runs, including on the failure paths, so the spans and
// metrics describing a failed scan are not the ones that get dropped.
func flushTelemetry(ctx context.Context, shutdown telemetry.ShutdownFunc) {
	if err := shutdown(ctx); err != nil {
		logger.L().Warning("failed to flush OpenTelemetry data", helpers.Error(err))
	}
}
