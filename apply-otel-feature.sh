#!/usr/bin/env bash
set -euo pipefail
# Run this from the ROOT of your kubescape repo checkout in WSL.
# Creates 2 new files and overwrites 7 existing files (full contents).
echo "Applying OTel exporter feature (issue #3402)..."

mkdir -p core/pkg/telemetry core/pkg/resultshandling/printer/v2

cat > core/pkg/telemetry/otel.go << 'KSEOF_UNIQUE_9f3a'
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
KSEOF_UNIQUE_9f3a

cat > core/pkg/resultshandling/printer/v2/otel.go << 'KSEOF_UNIQUE_9f3a'
package printer

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
)

// otelMeterName identifies kubescape's instrumentation scope to consumers of
// the exported metrics (e.g. shown as the "scope" in a Grafana/Prometheus
// OTel view). It intentionally mirrors core/metrics.METER_NAME's module-path
// convention.
const otelMeterName = "github.com/kubescape/kubescape/v4/scan"

var _ printer.IPrinter = &OtelPrinter{}

// OtelPrinter exports scan-level metrics through the OTel metrics API
// (go.opentelemetry.io/otel/metric), alongside the scan-phase spans already
// emitted via otel.Tracer("") throughout core/core/scan.go.
//
// Unlike the file-based printers (Prometheus included), it never writes an
// output file: metrics are pushed to whatever MeterProvider is registered
// globally via otel.SetMeterProvider (see core/pkg/telemetry.Setup, wired
// from --otel-endpoint / OTEL_EXPORTER_OTLP_ENDPOINT in cmd/scan). If no
// MeterProvider was registered because the flag/env var was never set,
// otel.GetMeterProvider() returns the OTel SDK's built-in no-op provider and
// every instrument recorded below becomes a cheap no-op -- this is what
// keeps the "otel" format free of runtime/dependency overhead when it isn't
// requested (see issue #3402 acceptance criteria).
type OtelPrinter struct {
	verboseMode bool
	// createdAt is set when the printer is constructed, which happens early
	// in core.GetOutputPrinters -- i.e. before resource collection starts.
	// ActionPrint (called once, after the full scan) measures elapsed time
	// against this, giving an approximate end-to-end scan duration without
	// needing a dedicated timer threaded through the scan pipeline.
	createdAt time.Time
}

// NewOtelPrinter constructs an OtelPrinter. verboseMode is accepted for
// symmetry with the other v2 printers' constructors; the otel format has no
// verbose/non-verbose distinction today.
func NewOtelPrinter(verboseMode bool) *OtelPrinter {
	return &OtelPrinter{
		verboseMode: verboseMode,
		createdAt:   time.Now(),
	}
}

func (op *OtelPrinter) PrintNextSteps() {}

// SetWriter is a no-op: the otel format exports over OTLP, not to a file.
// An explicit --output is accepted (so it does not break `--format
// otel,json --output report` style multi-format invocations) but ignored.
func (op *OtelPrinter) SetWriter(ctx context.Context, outputFile string) error {
	if outputFile != "" {
		logger.L().Ctx(ctx).Warning("--output is ignored for the \"otel\" format; metrics are exported via OTLP to --otel-endpoint instead of a file")
	}
	return nil
}

// Score is intentionally a no-op. The compliance score is already exported
// as part of ActionPrint's control counters; a separate Score() call (fired
// after ActionPrint, see resultshandling.ResultsHandler.HandleResults) would
// only duplicate it.
func (op *OtelPrinter) Score(score float32) {}

// CloseWriter satisfies the optional errorCloser contract; there is no file
// handle to close.
func (op *OtelPrinter) CloseWriter() error { return nil }

func (op *OtelPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	meter := otel.Meter(otelMeterName)

	if err := op.recordDuration(ctx, meter); err != nil {
		logger.L().Ctx(ctx).Warning("failed to record otel scan duration", helpers.Error(err))
	}

	switch {
	case opaSessionObj != nil:
		m := &Metrics{}
		m.setComplianceScores(&opaSessionObj.Report.SummaryDetails)

		if err := op.recordResourceCounts(ctx, meter, opaSessionObj.AllResources); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel resource counts", helpers.Error(err))
		}
		if err := op.recordControlCounts(ctx, meter, m); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel control counts", helpers.Error(err))
		}
	case len(imageScanData) > 0:
		if err := op.recordImageMetrics(ctx, meter, imageScanData); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel image metrics", helpers.Error(err))
		}
	default:
		return fmt.Errorf("failed to print results, missing data")
	}

	logger.L().Ctx(ctx).Success("Scan metrics exported via OTel")
	return nil
}

// recordDuration records the approximate scan duration. See createdAt's
// doc comment for what it measures and why.
func (op *OtelPrinter) recordDuration(ctx context.Context, meter metric.Meter) error {
	hist, err := meter.Float64Histogram(
		"kubescape_scan_duration_seconds",
		metric.WithDescription("Approximate wall-clock duration of the scan, from output-printer setup to results printing"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}
	hist.Record(ctx, time.Since(op.createdAt).Seconds())
	return nil
}

// recordResourceCounts records the number of collected Kubernetes resources,
// broken down by kind (issue #3402: "resource count by kind").
func (op *OtelPrinter) recordResourceCounts(ctx context.Context, meter metric.Meter, resources map[string]workloadinterface.IMetadata) error {
	gauge, err := meter.Int64Gauge(
		"kubescape_scan_resource_count",
		metric.WithDescription("Number of Kubernetes resources collected for the scan, by kind"),
	)
	if err != nil {
		return err
	}

	byKind := make(map[string]int64, len(resources))
	for _, r := range resources {
		byKind[r.GetKind()]++
	}
	for kind, count := range byKind {
		gauge.Record(ctx, count, metric.WithAttributes(attribute.String("kind", kind)))
	}
	return nil
}

// recordControlCounts records the total number of controls evaluated, and
// resource-level pass/fail counts grouped by control severity (issue #3402:
// "controls evaluated, controls passed/failed by severity").
func (op *OtelPrinter) recordControlCounts(ctx context.Context, meter metric.Meter, m *Metrics) error {
	evaluated, err := meter.Int64Gauge(
		"kubescape_scan_controls_evaluated",
		metric.WithDescription("Total number of controls evaluated by the scan"),
	)
	if err != nil {
		return err
	}
	evaluated.Record(ctx, int64(m.rs.controlsCountPassed+m.rs.controlsCountFailed+m.rs.controlsCountSkipped))

	result, err := meter.Int64Gauge(
		"kubescape_scan_controls_result",
		metric.WithDescription("Control evaluation results (resource-level pass/fail counts), grouped by control severity and status"),
	)
	if err != nil {
		return err
	}

	type tally struct{ passed, failed int64 }
	bySeverity := make(map[string]*tally)
	for i := range m.listControls {
		c := &m.listControls[i]
		t, ok := bySeverity[c.severity]
		if !ok {
			t = &tally{}
			bySeverity[c.severity] = t
		}
		t.passed += int64(c.resourcesCountPassed)
		t.failed += int64(c.resourcesCountFailed)
	}
	for severity, t := range bySeverity {
		result.Record(ctx, t.passed, metric.WithAttributes(attribute.String("severity", severity), attribute.String("status", "passed")))
		result.Record(ctx, t.failed, metric.WithAttributes(attribute.String("severity", severity), attribute.String("status", "failed")))
	}
	return nil
}

// recordImageMetrics records per-image, per-severity CVE counts for an image
// scan, mirroring PrometheusPrinter.generateImagePrometheusFormat (#2782) so
// the two formats stay consistent for image-scan consumers.
func (op *OtelPrinter) recordImageMetrics(ctx context.Context, meter metric.Meter, imageScanData []cautils.ImageScanData) error {
	m := &Metrics{isImageScan: true}
	m.setImageVulnerabilities(imageScanData)

	cve, err := meter.Int64Gauge(
		"kubescape_scan_image_cve_count",
		metric.WithDescription("Number of CVEs found per scanned image, by severity"),
	)
	if err != nil {
		return err
	}
	for _, iv := range m.listImages {
		cve.Record(ctx, int64(iv.cveCount),
			metric.WithAttributes(
				attribute.String("image", iv.image),
				attribute.String("severity", iv.severity),
			),
		)
	}
	return nil
}
KSEOF_UNIQUE_9f3a

cat > cmd/scan/scan.go << 'KSEOF_UNIQUE_9f3a'
package scan

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
)

var scanCmdExamples = fmt.Sprintf(`
  Scan command is for scanning an existing cluster or kubernetes manifest files based on pre-defined frameworks

  # Scan current cluster
  %[1]s scan

  # Scan kubernetes manifest files
  %[1]s scan .

  # Scan and save the results in the JSON format
  %[1]s scan --format json --output results.json

  # Scan and save the results in multiple format in a single scan
  %[1]s scan --format json,html,junit --output result

  # Display all resources
  %[1]s scan --verbose

  # Generate an anonymized report
  %[1]s scan --hide --format json -o report.json

  # The key is a passphrase of at least 16 characters. It is stretched into an
  # AES-256 key with Argon2id under a per-report salt, so length is what buys
  # you security here — prefer a long passphrase or generated key material.
  export KUBESCAPE_MASTER_KEY="$(openssl rand -base64 32)"
  # Hex-encoded key material works too, via a separate variable:
  # export KUBESCAPE_MASTER_KEY_HEX="$(openssl rand -hex 32)"
  %[1]s scan --encrypt --format json -o encrypted-report.json

  # Decrypt an encrypted report
  %[1]s decrypt encrypted-report.json > decrypted-report.json

  # Scan different clusters from the kubectl context
  %[1]s scan --kube-context <kubernetes context>

  # Compare a live scan against a saved baseline report and fail CI on new high-severity+ drift
  %[1]s scan --baseline base.json --baseline-fail-on-new --baseline-severity-threshold high
`, cautils.ExecName())

func GetScanCommand(ks meta.IKubescape) *cobra.Command {
	var scanInfo cautils.ScanInfo
	// otelShutdown flushes/releases the OTel providers registered by
	// telemetry.Setup in PersistentPreRunE below. It defaults to a no-op so
	// PersistentPostRunE can call it unconditionally, including on scan
	// invocations where --otel-endpoint/OTEL_EXPORTER_OTLP_ENDPOINT was never
	// set (the common case) or where PersistentPreRunE returned early on a
	// validation error before telemetry.Setup ran.
	var otelShutdown telemetry.ShutdownFunc = func(context.Context) error { return nil }

	// scanCmd represents the scan command
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan a Kubernetes cluster or YAML files for image vulnerabilities and misconfigurations",
		Long:    `Scan a Kubernetes cluster, YAML files, Helm charts, Kustomize directories, Git repositories, or container images for security misconfigurations and vulnerabilities.`,
		Example: scanCmdExamples,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// runs for the bare scan command and all subcommands (framework, control, workload, image)
			if scanInfo.FormatVersion != "v1" && scanInfo.FormatVersion != "v2" {
				return fmt.Errorf("invalid --format-version %q: supported versions are v1 and v2", scanInfo.FormatVersion)
			}
			if scanInfo.ScanTimeout < 0 {
				return fmt.Errorf("invalid --scan-timeout %s: must be zero or positive", scanInfo.ScanTimeout)
			}
			if scanInfo.ControlTimeout < 0 {
				return fmt.Errorf("invalid --control-timeout %s: must be zero or positive", scanInfo.ControlTimeout)
			}
			if strings.Contains(scanInfo.ControlsVersion, "/") {
				return fmt.Errorf(
					"invalid --controls-version %q: must be a regolibrary release tag and cannot contain '/'",
					scanInfo.ControlsVersion,
				)
			}
			if scanInfo.Baseline != "" && scanInfo.BaselineSeverityThreshold != "" {
				if err := shared.ValidateSeverity(scanInfo.BaselineSeverityThreshold); err != nil {
					return err
				}
			}
			captureKubeconfigSelection(cmd, &scanInfo)
			applyRegistryCredentialsFromEnv(cmd, &scanInfo)

			// OTel export (issue #3402): only touches the OTel SDK at all
			// when an endpoint was actually requested, so a bare `scan` run
			// never pays for it.
			if endpoint := telemetry.ResolveEndpoint(scanInfo.OtelEndpoint); endpoint != "" {
				shutdown, err := telemetry.Setup(cmd.Context(), endpoint, versioncheck.BuildNumber)
				if err != nil {
					return fmt.Errorf("failed to set up --otel-endpoint %q: %w", endpoint, err)
				}
				otelShutdown = shutdown
			}
			return nil
		},
		// PersistentPostRunE flushes OTel spans/metrics after the scan (and
		// result printing) has finished. cobra.EnableTraverseRunHooks (set in
		// cmd/root.go) makes this fire for every scan subcommand
		// (scan, scan control, scan framework, scan workload, scan image),
		// matching PersistentPreRunE's traversal above.
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return otelShutdown(shutdownCtx)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := shared.ValidateCommonScanFlags(cmd, &scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateCombinedImageScanFlags(&scanInfo); err != nil {
				return err
			}

			if scanInfo.EncryptionEnabled {

				if _, err := reportcrypto.GetMasterKeyFromEnv("encryption"); err != nil {
					return err
				}
			}

			requestedView := scanInfo.View

			if err := validateFrameworkScanInfo(&scanInfo); err != nil {
				return err
			}

			scanInfo.View = requestedView

			if scanInfo.View == string(cautils.SecurityViewType) {
				policyIdentifiers := setSecurityViewScanInfo(args, &scanInfo)

				if err := securityScan(scanInfo, ks, policyIdentifiers); err != nil {
					return err
				}
			} else {
				if err := getFrameworkCmd(
					ks,
					&scanInfo,
				).RunE(
					cmd,
					append(
						[]string{
							strings.Join(
								getter.NativeFrameworks,
								",",
							),
						},
						args...,
					),
				); err != nil {
					return err
				}
			}

			return nil
		},
	}

	scanInfo.TriggeredByCLI = true

	scanCmd.PersistentFlags().StringVarP(&scanInfo.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.AccessKey, "access-key", "", "", "Kubescape SaaS access key. Default will load access key from cache")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsInputs, "controls-config", "", "Path to an controls-config obj. If not set will download controls-config from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from ARMO management portal")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.AuditExceptions, "audit-exceptions", false, "Include an exception usage audit in supported scan outputs")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseArtifactsFrom, "use-artifacts-from", "", "Load artifacts from local directory. If not used will download them")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. e.g: --exclude-namespaces ns-a,ns-b. Notice, when running with `exclude-namespace` kubescape does not scan cluster-scoped objects.")
	scanCmd.PersistentFlags().StringVar(&scanInfo.MinSeverity, "min-severity", "", "Only include controls at or above this severity (low, medium, high, critical) in the output")
	scanCmd.PersistentFlags().StringVar(&scanInfo.MaxSeverity, "max-severity", "", "Only include controls at or below this severity (low, medium, high, critical) in the output")

	scanCmd.PersistentFlags().Float32VarP(&scanInfo.ComplianceThreshold, "compliance-threshold", "", 0, "Compliance threshold is the percent below which the command fails and returns exit code 1. Applies to 'scan framework', 'scan control', and '--view resource|control'")
	scanCmd.PersistentFlags().Float32Var(&scanInfo.FailCoverageThreshold, "fail-coverage-below", 0, "Fail (exit code 1) when the scan coverage score drops below this percentage (0 to disable). The score is the ratio of evaluated controls discounted by 3 points per silent failed GVR pull (a resource type that failed to collect entirely but whose dependent controls still evaluated via other resource types), 2 points per partial GVR pull, and 5 points per degraded policy input, so a scan with every control evaluated can still fail on partial resource collection or fallback policy inputs")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.FailOnDegradedConfig, "fail-on-degraded-config", false, "Fail the scan (exit code 1) if control configurations or exceptions could not be loaded from their configured source and bundled defaults were used instead")

	scanCmd.PersistentFlags().StringVar(&scanInfo.FailThresholdSeverity, "severity-threshold", "", "Severity threshold is the severity of failed controls at which the command fails and returns exit code 1. Failed controls whose severity is unknown (missing base score) are treated as exceeding any threshold")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.OnlyFixable, "only-fixable", false, "When used with --severity-threshold on image scans, only count CVEs that have an available fix toward the pass/fail decision")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsVersion, "controls-version", "", "Pin the regolibrary release tag used to download controls (see https://github.com/kubescape/regolibrary/releases). If not used will download the latest release. Has no effect when --account is set (cloud backend is used instead)")

	// --fail-threshold was removed as a functioning flag, but its registration must stay so
	// pflag/cobra keep accepting it instead of erroring with "unknown flag" for callers who
	// still pass it (e.g. existing CI pipelines). Same pattern as the --id/--environment/--env
	// deprecated-flag fix in cmd/list/list.go and cmd/root.go: bind to a standalone variable,
	// not scanInfo, so legacy input can't leak into report metadata or threshold validation.
	var dummyFailThreshold float32
	scanCmd.PersistentFlags().Float32VarP(&dummyFailThreshold, "fail-threshold", "t", 100, "Deprecated, use '--compliance-threshold' instead")
	_ = scanCmd.PersistentFlags().MarkHidden("fail-threshold")
	_ = scanCmd.PersistentFlags().MarkDeprecated("fail-threshold", "use '--compliance-threshold' flag instead")

	// Tri-state flag bound to the same BoolPtrFlag as the removed --enable-host-scan:
	// not passed -> auto-detect node-agent CRDs; --host-scan=false -> opt out of
	// host data collection; --host-scan=true -> force host data collection on.
	hostF := scanCmd.PersistentFlags().VarPF(&scanInfo.HostSensorEnabled, "host-scan", "", "Enable host data collection from cluster nodes for certain controls. When not set, Kubescape auto-detects node-agent CRDs and uses a CRD-based host sensor if available. Use --host-scan=false to disable host data collection. See https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator for the operator-based alternative")
	hostF.NoOptDefVal = "true"

	scanCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", fmt.Sprintf(`Output file format. Supported formats: "%s"`, strings.Join(shared.ScanFormats, `", "`)))
	scanCmd.PersistentFlags().StringVar(&scanInfo.IncludeNamespaces, "include-namespaces", "", "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	scanCmd.PersistentFlags().StringVar(&scanInfo.IncludeKinds, "include-kinds", "", "scan only the specified Kubernetes resource kinds (case-insensitive, Kind name only — not group/version qualified). e.g: --include-kinds Deployment,DaemonSet")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ExcludeKinds, "exclude-kinds", "", "exclude the specified Kubernetes resource kinds from the scan (case-insensitive, Kind name only — not group/version qualified). e.g: --exclude-kinds Job,CronJob")
	scanCmd.PersistentFlags().StringVar(&scanInfo.LabelSelector, "label-selector", "", "Filter collected Kubernetes resources by label selector. Accepts any selector that kubectl -l supports, e.g: --label-selector app=nginx,env!=dev")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Local, "keep-local", "", false, "If you do not want your Kubescape results reported to configured backend.")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display all of the input resources and not only failed resources")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.ShowEvidence, "show-evidence", "E", false, "Show evidence paths with current field values for each failed control (pretty-printer only)")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.ShowSecrets, "show-secrets", false, "Show secret field values in evidence output. By default secret values are redacted. Only effective with --show-evidence")
	scanCmd.PersistentFlags().StringVar(&scanInfo.View, "view", string(cautils.SecurityViewType), fmt.Sprintf("View results based on the %s/%s/%s. default is --view=%s", cautils.ResourceViewType, cautils.ControlViewType, cautils.SecurityViewType, cautils.SecurityViewType))
	scanCmd.PersistentFlags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load local policy object from default path. If not used will download latest")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.UseFrom, "use-from", nil, "Load local policy object from specified path. If not used will download latest")
	scanCmd.PersistentFlags().StringVar(&scanInfo.FormatVersion, "format-version", "v2", "Output object can be different between versions, this is for maintaining backward and forward compatibility. Supported:'v1'/'v2'")
	scanCmd.PersistentFlags().StringVar(&scanInfo.CustomClusterName, "cluster-name", "", "Set the custom name of the cluster. Not same as the kube-context flag")
	submitF := scanCmd.PersistentFlags().VarPF(&scanInfo.Submit, "submit", "", "Submit the scan results to Kubescape SaaS where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	submitF.NoOptDefVal = "true"
	submitF.DefValue = "false"
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.OmitRawResources, "omit-raw-resources", "", false, "Omit raw resources from the output. By default the raw resources are included in the output")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.PrintAttackTree, "print-attack-tree", "", false, "Print attack tree")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.EnableRegoPrint, "enable-rego-prints", "", false, "Enable sending to rego prints to the logs (use with debug log level: -l debug)")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.ScanImages, "scan-images", "", false, "Scan resources images")
	scanCmd.PersistentFlags().IntVar(&scanInfo.ImageScanConcurrency, "image-scan-concurrency", 1, "Number of concurrent workers for image scanning")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ImagePlatform, "image-platform", "", "OCI platform for --scan-images, for example linux/amd64; overrides platform inferred from workload scheduling constraints")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.UseDefaultMatchers, "use-default-matchers", "", true, "Use default matchers (true) or CPE matchers (false) for image scanning")
	scanCmd.PersistentFlags().StringToStringVar(&scanInfo.RegistryMapping, "registry-mapping", nil, "Map internal registry hosts to reachable ones, e.g. --registry-mapping image-registry.openshift-image-registry.svc:5000=registry.company.com (host[:port], no scheme)")
	scanCmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "Username for image registry login when no docker config or credential helper is available; can also be set with KUBESCAPE_REGISTRY_USERNAME")
	scanCmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "Password for image registry login when no docker config or credential helper is available; can also be set with KUBESCAPE_REGISTRY_PASSWORD")
	scanCmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "Bearer token for image registry login when no docker config or credential helper is available; can also be set with KUBESCAPE_REGISTRY_TOKEN")
	scanCmd.PersistentFlags().StringVar(&scanInfo.RegistryAuthority, "registry-authority", "", "Registry host[:port] the --scan-images credentials apply to")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.Hide, "hide", false, "Replace sensitive report metadata with deterministic pseudonyms")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.EncryptionEnabled, "encrypt", false, "Encrypt sensitive report metadata using the KUBESCAPE_MASTER_KEY environment variable")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.LabelsToCopy, "labels-to-copy", nil, "Labels to copy from workloads to scan reports for easy identification. e.g: --labels-to-copy=app,team,environment")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ListingURL, "grype-db-url", "", "Grype vulnerability database URL")
	scanCmd.PersistentFlags().DurationVar(&scanInfo.ScanTimeout, "scan-timeout", 0, "Maximum duration for the scan (e.g. 5m, 30s, 1h). 0 means no timeout. When the timeout is reached the scan exits with a non-zero code.")
	scanCmd.PersistentFlags().DurationVar(&scanInfo.ControlTimeout, "control-timeout", 0, "Maximum duration for evaluating a single control (e.g. 30s, 1m). 0 means no timeout. Controls that exceed this are marked as not evaluated and the scan continues. Must be lower than --scan-timeout when both are set.")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.EnableStreaming, "enable-streaming", false, "Enable resource streaming for large clusters to reduce memory usage. Resources are processed in batches instead of loading all at once. Automatically enabled for clusters with >2500 resources.")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.DryRun, "dry-run", false, "Check whether the current credentials can list every resource type the requested policies need, without collecting resources or evaluating controls. Cluster scans only.")
	scanCmd.PersistentFlags().StringVar(&scanInfo.OtelEndpoint, "otel-endpoint", "", "OTLP/gRPC endpoint (host:port, e.g. localhost:4317) to export scan spans and metrics to. Falls back to the OTEL_EXPORTER_OTLP_ENDPOINT env var. Unset by default: no OTel SDK is initialized and there is no export overhead. Combine with --format otel to also export scan-level metrics (duration, resource/control counts) as a printer, in addition to the always-on spans this flag enables")

	// Helm value override flags. Mirror `helm install` so users can pass overrides through verbatim
	// when scanning a Helm chart directory. Note: -f is already taken by --format, so --values is long-only.
	//
	// Flag-binding choices match upstream Helm (helm.sh/helm/v3 cmd/helm/flags.go) exactly:
	//   --values     -> StringSliceVar : Helm splits on commas, so `--values a.yaml,b.yaml` is two files.
	//   --set        -> StringArrayVar : verbatim; commas inside the value belong to the strvals parser
	//                                    and must survive (e.g. `--set tolerations={a,b}`).
	//   --set-string -> StringArrayVar : same reasoning as --set.
	//   --set-file   -> StringArrayVar : same reasoning as --set.
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.HelmValueFiles, "values", nil, "Specify Helm values in a YAML file or a URL when scanning a Helm chart (can specify multiple, or separate paths with commas)")
	scanCmd.PersistentFlags().StringArrayVar(&scanInfo.HelmSetValues, "set", nil, "Set Helm values on the command line when scanning a Helm chart (can specify multiple, e.g. --set key1=val1 --set key2=val2)")
	scanCmd.PersistentFlags().StringArrayVar(&scanInfo.HelmSetStringValues, "set-string", nil, "Set Helm STRING values on the command line when scanning a Helm chart (can specify multiple)")
	scanCmd.PersistentFlags().StringArrayVar(&scanInfo.HelmSetFileValues, "set-file", nil, "Set Helm values from respective files specified via the command line (can specify multiple)")
	scanCmd.PersistentFlags().StringVar(&scanInfo.HelmReleaseName, "release-name", "", "Helm release name made available as .Release.Name when rendering the chart")
	scanCmd.PersistentFlags().StringVar(&scanInfo.HelmReleaseNamespace, "release-namespace", "", "Helm release namespace made available as .Release.Namespace when rendering the chart")

	// hidden flags
	_ = scanCmd.PersistentFlags().MarkHidden("omit-raw-resources") // #nosec G104 -- flag defined on this command; MarkHidden only errors for an unknown flag
	_ = scanCmd.PersistentFlags().MarkHidden("print-attack-tree")  // #nosec G104 -- flag defined on this command; MarkHidden only errors for an unknown flag
	_ = scanCmd.PersistentFlags().MarkHidden("format-version")     // #nosec G104 -- flag defined on this command; MarkHidden only errors for an unknown flag

	// Retrieve --kubeconfig flag from https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/cmd.go
	scanCmd.PersistentFlags().AddGoFlag(flag.Lookup("kubeconfig"))

	scanCmd.PersistentFlags().StringVar(&scanInfo.Baseline, "baseline", "", "Path to a saved JSON scan report to diff the fresh scan against.")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.BaselineFailOnNew, "baseline-fail-on-new", false, "With --baseline, exit with code 1 when new failures are found versus the baseline.")
	scanCmd.PersistentFlags().StringVar(&scanInfo.BaselineSeverityThreshold, "baseline-severity-threshold", "", "With --baseline, only count new failures at or above this severity when using --baseline-fail-on-new.")
	scanCmd.PersistentFlags().StringVar(&scanInfo.BaselineGranularity, "baseline-granularity", "evidence", "With --baseline, comparison unit: evidence or control.")

	scanCmd.AddCommand(getControlCmd(ks, &scanInfo))
	scanCmd.AddCommand(getFrameworkCmd(ks, &scanInfo))
	scanCmd.AddCommand(getWorkloadCmd(ks, &scanInfo))

	scanCmd.AddCommand(getImageCmd(ks, &scanInfo))

	return scanCmd
}

func validateCombinedImageScanFlags(scanInfo *cautils.ScanInfo) error {
	if scanInfo == nil || !scanInfo.ScanImages {
		return nil
	}
	if err := shared.ValidateImageScanInfo(scanInfo); err != nil {
		return err
	}
	return shared.ValidateWorkloadImageCredentials(shared.ImageCredentials{
		Authority: scanInfo.RegistryAuthority,
		Username:  scanInfo.RegistryUsername,
		Password:  scanInfo.RegistryPassword,
		Token:     scanInfo.RegistryToken,
	})
}

func applyRegistryCredentialsFromEnv(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
	if scanInfo == nil {
		return
	}
	usernameFlagChanged := shared.RegistryCredentialFlagChanged(cmd, "registry-username", "username")
	passwordFlagChanged := shared.RegistryCredentialFlagChanged(cmd, "registry-password", "password")
	tokenFlagChanged := shared.RegistryCredentialFlagChanged(cmd, "registry-token")

	if !tokenFlagChanged && !usernameFlagChanged && scanInfo.RegistryUsername == "" {
		scanInfo.RegistryUsername = os.Getenv(shared.RegistryUsernameEnvVar)
	}
	if !tokenFlagChanged && !passwordFlagChanged && scanInfo.RegistryPassword == "" {
		scanInfo.RegistryPassword = os.Getenv(shared.RegistryPasswordEnvVar)
	}
	if !tokenFlagChanged && !usernameFlagChanged && !passwordFlagChanged && scanInfo.RegistryToken == "" {
		scanInfo.RegistryToken = os.Getenv(shared.RegistryTokenEnvVar)
	}
}

func setSecurityViewScanInfo(args []string, scanInfo *cautils.ScanInfo) []cautils.PolicyIdentifier {
	if len(args) > 0 {
		scanInfo.SetScanType(cautils.ScanTypeRepo)
		scanInfo.InputPatterns = args
		return cautils.BuildPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)
	}
	scanInfo.SetScanType(cautils.ScanTypeCluster)
	return cautils.BuildPolicyIdentifiers([]string{"clusterscan", "mitre", "nsa"}, v1.KindFramework)
}

// applyTimeout wraps ks with a deadline context when ScanTimeout > 0 and
// returns a cleanup function that cancels the context and restores the
// original. The caller must defer the returned function so the deadline
// covers both ks.Scan() and results.HandleResults().
//
//	defer applyTimeout(scanInfo, ks)()
func applyTimeout(scanInfo *cautils.ScanInfo, ks meta.IKubescape) func() {
	if scanInfo.ScanTimeout <= 0 {
		return func() {}
	}
	originalCtx := ks.Context()
	timeoutCtx, cancel := context.WithTimeout(originalCtx, scanInfo.ScanTimeout)
	ks.SetContext(timeoutCtx)
	return func() {
		cancel()
		ks.SetContext(originalCtx)
	}
}

// handleResultsWithReportingSpan wraps results.HandleResults in a
// "reporting" span, alongside the "initialization" / "policies" /
// "resources" / "opa testing" spans core/core/scan.go already emits via
// otel.Tracer(""), so a scan's exported OTel trace covers the full pipeline
// through result printing and submission (issue #3402).
func handleResultsWithReportingSpan(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) error {
	ctx, span := otel.Tracer("").Start(ctx, "reporting")
	defer span.End()
	return results.HandleResults(ctx, scanInfo)
}

func securityScan(scanInfo cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) error {
	defer applyTimeout(&scanInfo, ks)()

	results, err := ks.Scan(&scanInfo, policyIdentifiers)
	if err != nil {
		return err
	}

	if err = handleResultsWithReportingSpan(ks.Context(), results, &scanInfo); err != nil {
		return err
	}

	if err := enforceSeverityThresholds(&results.GetData().Report.SummaryDetails, &scanInfo); err != nil {
		return err
	}
	if scanInfo.ScanImages {
		if err := enforceImageSeverityThresholds(results.ImageScanData, &scanInfo); err != nil {
			return err
		}
	}
	if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), &scanInfo); err != nil {
		return err
	}
	if err := enforcePolicyDegradation(results.GetData().ScanCoverage, &scanInfo); err != nil {
		return err
	}

	return enforceBaselineDrift(ks.Context(), results, &scanInfo)
}

func enforceBaselineDrift(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) error {
	newFailures, err := core.EnforceBaseline(ctx, results, scanInfo)
	if err != nil {
		return err
	}
	if scanInfo.BaselineFailOnNew && newFailures > 0 {
		return fmt.Errorf("baseline drift: found %d new failure(s) at or above baseline severity threshold %q", newFailures, severityLabelOrAll(scanInfo.BaselineSeverityThreshold))
	}
	return nil
}

func severityLabelOrAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func enforceImageSeverityThresholds(imageScanData []cautils.ImageScanData, scanInfo *cautils.ScanInfo) error {
	if scanInfo.FailThresholdSeverity == "" {
		return nil
	}

	thresholdSeverity := imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)
	if thresholdSeverity == vulnerability.UnknownSeverity {
		return nil
	}

	for _, data := range imageScanData {
		for m := range data.Matches.Enumerate() {
			metadata := m.Vulnerability.Metadata
			if metadata == nil || imagescan.ParseSeverity(metadata.Severity) == vulnerability.UnknownSeverity {
				if data.VulnerabilityProvider == nil {
					continue
				}
				var err error
				//nolint:staticcheck // fallback for matches without a known embedded severity
				metadata, err = data.VulnerabilityProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
				if err != nil {
					continue
				}
			}

			if imagescan.ParseSeverity(metadata.Severity) >= thresholdSeverity &&
				(!scanInfo.OnlyFixable || m.Vulnerability.Fix.State == vulnerability.FixStateFixed) {
				return fmt.Errorf("image scan result exceeds severity threshold: %s", scanInfo.FailThresholdSeverity)
			}
		}
	}
	return nil
}
KSEOF_UNIQUE_9f3a

cat > cmd/scan/control.go << 'KSEOF_UNIQUE_9f3a'
package scan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
)

var (
	controlExample = fmt.Sprintf(`
  # Scan the 'privileged container' control
  %[1]s scan control "privileged container"
	
  # Scan list of controls separated with a comma
  %[1]s scan control "privileged container","HostPath mount"
  
  # Scan list of controls using the control ID separated with a comma
  %[1]s scan control C-0058,C-0057
  
  Run '%[1]s list controls' for the list of supported controls
  
  Control documentation:
  https://kubescape.io/docs/controls/
`, cautils.ExecName())
)

// controlCmd represents the control command
func getControlCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	return &cobra.Command{
		Use:     "control <control names list>/<control ids list>",
		Short:   fmt.Sprintf("The controls you wish to use. Run '%[1]s list controls' for the list of supported controls", cautils.ExecName()),
		Example: controlExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				controls := strings.Split(args[0], ",")
				if len(controls) > 1 {
					if slices.Contains(controls, "") {
						return fmt.Errorf("usage: <control-0>,<control-1>")
					}
				}
			} else {
				return fmt.Errorf("requires at least one control name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateFrameworkScanInfo(scanInfo); err != nil {
				return err
			}

			// flagValidationControl(scanInfo)
			var policyIdentifiers []cautils.PolicyIdentifier

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else { // expected control or list of control separated by ","

				// Read controls from input args
				policyIdentifiers = cautils.BuildPolicyIdentifiers(strings.Split(args[0], ","), apisv1.KindControl)

				cleanup, err := prepareScanLocalInput(cmd.InOrStdin(), args, scanInfo, scanLocalInputOptions{
					FirstInputArg:    1,
					RejectMixedStdin: true,
				})
				if err != nil {
					return err
				}
				defer cleanup()
			}

			scanInfo.FrameworkScan = false
			scanInfo.SetScanType(cautils.ScanTypeControl)

			if err := validateControlScanInfo(scanInfo); err != nil {
				return err
			}
			if err := validateCombinedImageScanFlags(scanInfo); err != nil {
				return err
			}

			results, err := ks.Scan(scanInfo, policyIdentifiers)
			if err != nil {
				return err
			}
			if err := handleResultsWithReportingSpan(ks.Context(), results, scanInfo); err != nil {
				return err
			}
			if !scanInfo.VerboseMode {
				logger.L().Info("Run with '--verbose'/'-v' flag for detailed resources view\n")
			}
			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				return fmt.Errorf("scan compliance-score is below permitted threshold: %.2f (compliance-threshold: %.2f)", results.GetComplianceScore(), scanInfo.ComplianceThreshold)
			}
			if err := enforceSeverityThresholds(&results.GetResults().SummaryDetails, scanInfo); err != nil {
				return err
			}
			if scanInfo.ScanImages {
				if err := enforceImageSeverityThresholds(results.ImageScanData, scanInfo); err != nil {
					return err
				}
			}
			if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetResults().SummaryDetails.Controls), scanInfo); err != nil {
				return err
			}
			if err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
				return err
			}

			return enforceBaselineDrift(ks.Context(), results, scanInfo)
		},
	}
}

// validateControlScanInfo validates the ScanInfo struct for the `control` command
func validateControlScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if err := validateControlTimeout(scanInfo); err != nil {
		return err
	}

	if err := shared.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}
	if err := validateThresholdsOnly(scanInfo); err != nil {
		return err
	}
	return nil
}
KSEOF_UNIQUE_9f3a

cat > cmd/scan/framework.go << 'KSEOF_UNIQUE_9f3a'
package scan

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/meta"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	frameworkExample = fmt.Sprintf(`
  # Scan all frameworks
  %[1]s scan framework all
  
  # Scan the NSA framework
  %[1]s scan framework nsa
  
  # Scan the NSA and MITRE framework
  %[1]s scan framework nsa,mitre
  
  # Scan all frameworks
  %[1]s scan framework all

  # Scan kubernetes YAML manifest files (single file or glob)
  %[1]s scan framework nsa .

  Run '%[1]s list frameworks' for the list of supported frameworks
`, cautils.ExecName())

	ErrSecurityViewNotSupported = errors.New("security view is not supported for framework scan")
	ErrBadThreshold             = errors.New("bad argument: out of range threshold")
	ErrControlTimeoutTooHigh    = errors.New("--control-timeout must be lower than --scan-timeout")
)

func getFrameworkCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {

	return &cobra.Command{
		Use:     "framework <framework names list> [`<glob pattern>`/`-`] [flags]",
		Short:   fmt.Sprintf("The framework you wish to use. Run '%[1]s list frameworks' for the list of supported frameworks", cautils.ExecName()),
		Example: frameworkExample,
		Long:    "Execute a scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				frameworks := strings.Split(args[0], ",")
				if len(frameworks) > 1 {
					if slices.Contains(frameworks, "") {
						return fmt.Errorf("usage: <framework-0>,<framework-1>")
					}
				}
			} else {
				return fmt.Errorf("requires at least one framework name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateFrameworkScanInfo(scanInfo); err != nil {
				return err
			}
			if err := validateCombinedImageScanFlags(scanInfo); err != nil {
				return err
			}
			scanInfo.FrameworkScan = true

			// We do not scan all frameworks by default when triggering scan from the CLI
			scanInfo.ScanAll = false

			var frameworks []string

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else {
				// Read frameworks from input args
				frameworks = strings.Split(args[0], ",")
				if slices.Contains(frameworks, "all") {
					scanInfo.ScanAll = true
					frameworks = getter.NativeFrameworks

				}
				cleanup, err := prepareScanLocalInput(cmd.InOrStdin(), args, scanInfo, scanLocalInputOptions{
					FirstInputArg:    1,
					RejectMixedStdin: true,
				})
				if err != nil {
					return err
				}
				defer cleanup()
				if len(scanInfo.InputPatterns) > 0 {
					logger.L().Debug("List of input files", helpers.Interface("patterns", scanInfo.InputPatterns))
				}
			}
			scanInfo.SetScanType(cautils.ScanTypeFramework)

			policyIdentifiers := cautils.BuildPolicyIdentifiers(frameworks, apisv1.KindFramework)

			results, err := ks.Scan(scanInfo, policyIdentifiers)
			if err != nil {
				return err
			}

			if err = handleResultsWithReportingSpan(ks.Context(), results, scanInfo); err != nil {
				return err
			}

			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				return fmt.Errorf("scan compliance-score is below permitted threshold: %.2f (compliance-threshold: %.2f)", results.GetComplianceScore(), scanInfo.ComplianceThreshold)
			}

			if err := enforceSeverityThresholds(&results.GetData().Report.SummaryDetails, scanInfo); err != nil {
				return err
			}
			if scanInfo.ScanImages {
				if err := enforceImageSeverityThresholds(results.ImageScanData, scanInfo); err != nil {
					return err
				}
			}
			if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), scanInfo); err != nil {
				return err
			}
			if err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
				return err
			}
			return enforceBaselineDrift(ks.Context(), results, scanInfo)
		},
	}

}

// countersExceedSeverityThreshold returns true if a failed control has severity
// at or above the configured threshold.
func countersExceedSeverityThreshold(severityCounters reportsummary.ISeverityCounters, scanInfo *cautils.ScanInfo) (bool, error) {
	targetSeverity := scanInfo.FailThresholdSeverity
	if err := shared.ValidateSeverity(targetSeverity); err != nil {
		return false, err
	}

	getFailedResourcesFuncsBySeverity := []struct {
		SeverityName       string
		GetFailedResources func() int
	}{
		{reporthandlingapis.SeverityLowString, severityCounters.NumberOfLowSeverity},
		{reporthandlingapis.SeverityMediumString, severityCounters.NumberOfMediumSeverity},
		{reporthandlingapis.SeverityHighString, severityCounters.NumberOfHighSeverity},
		{reporthandlingapis.SeverityCriticalString, severityCounters.NumberOfCriticalSeverity},
	}

	targetSeverityIdx := 0
	for idx, description := range getFailedResourcesFuncsBySeverity {
		if strings.EqualFold(description.SeverityName, targetSeverity) {
			targetSeverityIdx = idx
			break
		}
	}

	for _, description := range getFailedResourcesFuncsBySeverity[targetSeverityIdx:] {
		failedResourcesCount := description.GetFailedResources()
		if failedResourcesCount > 0 {
			return true, nil
		}
	}

	return false, nil

}

// enforceCoverageThreshold fails the scan if the scan coverage score is below
// scanInfo.FailCoverageThreshold. The score is computed once in the scan
// pipeline (ScanCoverage.ComputeCoverageScore) so this gate agrees with what
// the JSON, Prometheus and pretty-printer outputs report. A threshold of 0
// disables the check.
func enforceCoverageThreshold(coverage cautils.ScanCoverage, totalControls int, scanInfo *cautils.ScanInfo) error {
	if scanInfo.FailCoverageThreshold <= 0 {
		return nil
	}
	if totalControls == 0 {
		return fmt.Errorf("scan loaded no controls: coverage is 0%% (fail-coverage-below: %.2f%%)", scanInfo.FailCoverageThreshold)
	}
	if coverage.CoverageScore < scanInfo.FailCoverageThreshold {
		return fmt.Errorf("scan coverage is below permitted threshold: %.2f%% (fail-coverage-below: %.2f%%)", coverage.CoverageScore, scanInfo.FailCoverageThreshold)
	}
	return nil
}

// enforcePolicyDegradation fails the scan if control configurations or
// exceptions could not be loaded from their configured source and the scan
// proceeded with bundled defaults instead.
func enforcePolicyDegradation(coverage cautils.ScanCoverage, scanInfo *cautils.ScanInfo) error {
	if !scanInfo.FailOnDegradedConfig || len(coverage.PolicyDegradations) == 0 {
		return nil
	}
	for _, d := range coverage.PolicyDegradations {
		logger.L().Warning("policy input degraded, bundled defaults were used", helpers.String("component", d.Component), helpers.String("reason", d.Reason))
	}
	return fmt.Errorf("scan policy inputs were degraded (fail-on-degraded-config is true)")
}

// countFailedResourcesWithUnbucketedSeverity returns the number of failed
// resources on controls whose severity SeverityCounters.Increase silently
// drops: Unknown, Negligible, and any other severity it has no bucket for.
// The severity is derived from the control's score factor the same way
// SummaryDetails.AppendResourceResult derives it when feeding the counters.
func countFailedResourcesWithUnbucketedSeverity(summaryDetails *reportsummary.SummaryDetails) int {
	count := 0
	for _, controlSummary := range summaryDetails.Controls {
		switch reporthandlingapis.ControlSeverityToString(controlSummary.GetScoreFactor()) {
		case reporthandlingapis.SeverityCriticalString,
			reporthandlingapis.SeverityHighString,
			reporthandlingapis.SeverityMediumString,
			reporthandlingapis.SeverityLowString:
		default:
			count += controlSummary.StatusCounters.Failed()
		}
	}
	return count
}

// enforceSeverityThresholds ensures that the scan results are below the defined severity threshold
//
// The function returns an error if at least one failed control has a severity at or above the set severity threshold
func enforceSeverityThresholds(summaryDetails *reportsummary.SummaryDetails, scanInfo *cautils.ScanInfo) error {
	// If a severity threshold is not set, we don’t need to enforce it
	if scanInfo.FailThresholdSeverity == "" {
		return nil
	}

	if val, err := countersExceedSeverityThreshold(summaryDetails.GetResourcesSeverityCounters(), scanInfo); val && err == nil {
		return fmt.Errorf("compliance result exceeds severity threshold: %s", scanInfo.FailThresholdSeverity)
	} else if err != nil {
		return err
	}

	// Failed controls with a zero or missing baseScore never reach the
	// counters above, so a threshold could pass on findings whose severity
	// cannot be determined. Fail closed: treat them as at or above any
	// threshold the user set.
	if unbucketed := countFailedResourcesWithUnbucketedSeverity(summaryDetails); unbucketed > 0 {
		logger.L().Warning("failed resources with unknown severity counted toward the severity threshold", helpers.Int("failedResources", unbucketed))
		return fmt.Errorf("compliance result exceeds severity threshold: %s (%d failed resource(s) with unknown severity)", scanInfo.FailThresholdSeverity, unbucketed)
	}
	return nil
}

// validateFrameworkScanInfo validates the scan info struct for the `scan framework` command
func validateFrameworkScanInfo(scanInfo *cautils.ScanInfo) error {
	if scanInfo.View == string(cautils.SecurityViewType) {
		scanInfo.View = string(cautils.ResourceViewType)
	}
	if postureThresholdsOutOfRange(scanInfo) {
		return ErrBadThreshold
	}
	if err := validateControlTimeout(scanInfo); err != nil {
		return err
	}
	severity := scanInfo.FailThresholdSeverity
	if err := shared.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}

	if scanInfo.LabelSelector != "" {
		if _, err := labels.Parse(scanInfo.LabelSelector); err != nil {
			return fmt.Errorf("invalid --label-selector %q: %w", scanInfo.LabelSelector, err)
		}
	}

	// Validate the user's credentials
	return cautils.ValidateAccountID(scanInfo.AccountID)
}

// validateControlTimeout ensures --control-timeout, when set alongside
// --scan-timeout, leaves room for at least one control to be evaluated
// before the overall scan deadline expires.
func validateControlTimeout(scanInfo *cautils.ScanInfo) error {
	if scanInfo.ControlTimeout > 0 && scanInfo.ScanTimeout > 0 && scanInfo.ControlTimeout >= scanInfo.ScanTimeout {
		return ErrControlTimeoutTooHigh
	}
	return nil
}

// validateThresholdsOnly validates only the numeric threshold ranges
// (compliance-threshold and fail-coverage-threshold must be between 0 and 100).
// Unlike validateFrameworkScanInfo, this function does not mutate scanInfo
// or enforce unrelated constraints.
func validateThresholdsOnly(scanInfo *cautils.ScanInfo) error {
	if postureThresholdsOutOfRange(scanInfo) {
		return ErrBadThreshold
	}
	return validateControlTimeout(scanInfo)
}

func postureThresholdsOutOfRange(scanInfo *cautils.ScanInfo) bool {
	return math.IsNaN(float64(scanInfo.ComplianceThreshold)) ||
		math.IsNaN(float64(scanInfo.FailCoverageThreshold)) ||
		scanInfo.ComplianceThreshold < 0 || scanInfo.ComplianceThreshold > 100 ||
		scanInfo.FailCoverageThreshold < 0 || scanInfo.FailCoverageThreshold > 100
}
KSEOF_UNIQUE_9f3a

cat > cmd/scan/workload.go << 'KSEOF_UNIQUE_9f3a'
package scan

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/spf13/cobra"
)

var (
	workloadExample = fmt.Sprintf(`
  Scan a workload for misconfigurations and image vulnerabilities.

  # Scan a workload
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name>
	
  # Scan a specific kind, version, and group
  %[1]s scan workload Deployment.v1.apps/nginx

  # Scan an workload from a file path
  %[1]s scan workload <kind>/<name> --file-path <file path>

  # Scan a workload from local manifests
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> ./manifests

  # Scan a workload from a specific file path
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --file-path <file path>
  # Scan an workload with a specific API version
  %[1]s scan workload <kind>/<name> --api-version <api version>
  
  # Scan a workload from a helm-chart template
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --chart-path <chart path> --file-path <file path>


`, cautils.ExecName())

	ErrInvalidWorkloadIdentifier = errors.New("invalid workload identifier, expected <kind>[.<version>[.<group>]]/<name>")
)

// controlCmd represents the control command
func getWorkloadCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	var apiVersion string

	workloadCmd := &cobra.Command{
		Use:     "workload <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]",
		Short:   "Scan a workload for misconfigurations and image vulnerabilities",
		Example: workloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			return validateWorkloadArgs(args, scanInfo)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

			if err := validateWorkloadArgs(args, scanInfo); err != nil {
				return err
			}
			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateThresholdsOnly(scanInfo); err != nil {
				return err
			}
			if scanInfo.LabelSelector != "" {
				return fmt.Errorf("--label-selector is not supported for workload scans: the named resource is fetched by identity, not by label")
			}
			namespace, kind, name, workloadAPIVersion, err := parseWorkloadIdentifierString(args[0])
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			if namespace != "" && scanInfo.Namespace == "" {
				scanInfo.Namespace = namespace
			}

			cleanup, err := prepareWorkloadInput(cmd.InOrStdin(), args, scanInfo)
			if err != nil {
				return err
			}
			defer cleanup()

			if apiVersion == "" {
				apiVersion = workloadAPIVersion
			}

			policyIdentifiers := setWorkloadScanInfo(scanInfo, kind, name, apiVersion)
			if err := validateCombinedImageScanFlags(scanInfo); err != nil {
				return err
			}

			results, err := ks.Scan(scanInfo, policyIdentifiers)
			if err != nil {
				return err
			}

			if err = handleResultsWithReportingSpan(ks.Context(), results, scanInfo); err != nil {
				return err
			}

			if err := enforceSeverityThresholds(&results.GetData().Report.SummaryDetails, scanInfo); err != nil {
				return err
			}
			if scanInfo.ScanImages {
				if err := enforceImageSeverityThresholds(results.ImageScanData, scanInfo); err != nil {
					return err
				}
			}
			if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), scanInfo); err != nil {
				return err
			}
			if err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
				return err
			}

			return enforceBaselineDrift(ks.Context(), results, scanInfo)
		},
	}

	workloadCmd.PersistentFlags().StringVarP(&scanInfo.Namespace, "namespace", "n", "", "Namespace of the workload. Default will be empty.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.FilePath, "file-path", "", "Path to the workload file.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.ChartPath, "chart-path", "", "Path to the helm chart the workload is part of. Must be used with --file-path.")
	workloadCmd.PersistentFlags().StringVar(&apiVersion, "api-version", "", "API version of the workload (e.g. apps/v1). Default will be empty.")

	return workloadCmd
}

func validateWorkloadArgs(args []string, scanInfo *cautils.ScanInfo) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]")
	}

	if scanInfo.ChartPath != "" && scanInfo.FilePath == "" {
		return fmt.Errorf("usage: --chart-path <chart path> --file-path <file path>")
	}

	if scanInfo.FilePath != "" && len(args) > 1 {
		return fmt.Errorf("usage: use either --file-path or positional input paths, not both")
	}

	for _, arg := range args[1:] {
		if arg == "-" && len(args) > 2 {
			return fmt.Errorf("usage: stdin input '-' cannot be combined with other input paths")
		}
	}

	return validateWorkloadIdentifier(args[0])
}

func prepareWorkloadInput(stdin io.Reader, args []string, scanInfo *cautils.ScanInfo) (func(), error) {
	return prepareScanLocalInput(stdin, args, scanInfo, scanLocalInputOptions{
		FirstInputArg:    1,
		FilePath:         scanInfo.FilePath,
		RejectMixedStdin: true,
	})
}

func setWorkloadScanInfo(scanInfo *cautils.ScanInfo, kind string, name string, apiVersion string) []cautils.PolicyIdentifier {
	scanInfo.SetScanType(cautils.ScanTypeWorkload)
	scanInfo.ScanImages = true

	scanInfo.ScanObject = &objectsenvelopes.ScanObject{}
	scanInfo.ScanObject.SetNamespace(scanInfo.Namespace)
	if apiVersion != "" {
		scanInfo.ScanObject.SetApiVersion(apiVersion)
	}
	scanInfo.ScanObject.SetKind(kind)
	scanInfo.ScanObject.SetName(name)

	policyIdentifiers := cautils.BuildPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)

	if scanInfo.FilePath != "" && len(scanInfo.InputPatterns) == 0 {
		scanInfo.InputPatterns = []string{scanInfo.FilePath}
	}

	return policyIdentifiers
}

func validateWorkloadIdentifier(workloadIdentifier string) error {
	_, _, _, _, err := parseWorkloadIdentifierString(workloadIdentifier)
	return err
}

func parseWorkloadIdentifierString(workloadIdentifier string) (namespace, kind, name, apiVersion string, err error) {
	// workloadIdentifier is in the form of kind/name or namespace/kind/name
	// example: default/Deployment/nginx-deployment
	x := strings.Split(workloadIdentifier, "/")
	if len(x) == 2 {
		if x[0] == "" || x[1] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[0])
		if err != nil {
			return "", "", "", "", err
		}
		return "", parsedKind, x[1], parsedApiVersion, nil
	}
	if len(x) == 3 {
		if x[0] == "" || x[1] == "" || x[2] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[1])
		if err != nil {
			return "", "", "", "", err
		}
		return x[0], parsedKind, x[2], parsedApiVersion, nil
	}

	return "", "", "", "", ErrInvalidWorkloadIdentifier
}

var apiVersionPattern = regexp.MustCompile(`^v\d+((alpha|beta)\d+)?$`)

func parseKindAndApiVersion(kindStr string) (kind, apiVersion string, err error) {
	parts := strings.Split(kindStr, ".")
	if len(parts) == 1 {
		return kindStr, "", nil
	}

	// Reject empty components
	for _, part := range parts {
		if part == "" {
			return "", "", fmt.Errorf("%w: empty component in %q", ErrInvalidWorkloadIdentifier, kindStr)
		}
	}

	if !apiVersionPattern.MatchString(parts[1]) {
		return "", "", fmt.Errorf("%w: %q is not a valid API version in %q", ErrInvalidWorkloadIdentifier, parts[1], kindStr)
	}

	if len(parts) >= 3 {
		group := strings.Join(parts[2:], ".")
		return parts[0], group + "/" + parts[1], nil // kind.version.group -> group/version
	}
	return parts[0], parts[1], nil // kind.version -> version
}
KSEOF_UNIQUE_9f3a

cat > core/cautils/scaninfo.go << 'KSEOF_UNIQUE_9f3a'
package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/backend/pkg/versioncheck"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"k8s.io/client-go/tools/clientcmd"
)

type ScanningContext string

const (
	ContextCluster   ScanningContext = "cluster"
	ContextFile      ScanningContext = "single-file"
	ContextDir       ScanningContext = "local-dir"
	ContextGitLocal  ScanningContext = "git-local"
	ContextGitRemote ScanningContext = "git-remote"
)

const ( // deprecated
	ScopeCluster = "cluster"
)
const (
	LocalControlInputsFilename string = "controls-inputs.json"
	LocalExceptionsFilename    string = "exceptions.json"
	LocalAttackTracksFilename  string = "attack-tracks.json"
)

type BoolPtrFlag struct {
	valPtr *bool
}

func NewBoolPtr(b *bool) BoolPtrFlag {
	return BoolPtrFlag{valPtr: b}
}

func (bpf *BoolPtrFlag) Type() string {
	return "bool"
}

func (bpf *BoolPtrFlag) String() string {
	if bpf.valPtr != nil {
		return fmt.Sprintf("%v", *bpf.valPtr)
	}
	return ""
}
func (bpf *BoolPtrFlag) Get() *bool {
	return bpf.valPtr
}
func (bpf *BoolPtrFlag) GetBool() bool {
	if bpf.valPtr == nil {
		return false
	}
	return *bpf.valPtr
}

func (bpf *BoolPtrFlag) SetBool(val bool) {
	bpf.valPtr = &val
}

func (bpf *BoolPtrFlag) Set(val string) error {
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return err
	}
	bpf.SetBool(parsed)
	return nil
}

// ViewTypes specifies how scan results are presented by the default (pretty) printer.
type ViewTypes string

const (
	// ResourceViewType prints one section per failed resource, listing the
	// controls that failed it. It only takes effect in verbose mode; passed
	// resources are not shown.
	ResourceViewType ViewTypes = "resource"

	// SecurityViewType is the default view (see the --view flag). Rather than
	// changing how results are grouped, it selects a security-oriented set of
	// frameworks to scan with — workloadscan+allcontrols for a repository or
	// directory target, clusterscan+mitre+nsa for a cluster — and prints the
	// standard posture summary without per-control or per-resource detail.
	// Note: the `scan framework` subcommand rewrites this to ResourceViewType.
	SecurityViewType ViewTypes = "security"

	// ControlViewType groups results by control, showing the compliance status
	// of every control and the resources that failed it. Failed and
	// action-required resources are always listed, and passed resources are
	// listed in verbose mode.
	ControlViewType ViewTypes = "control"
)

type PolicyIdentifier struct {
	Identifier string                        // policy Identifier e.g. c-0012 for control, nsa,mitre for frameworks
	Kind       apisv1.NotificationPolicyKind // policy kind e.g. Framework,Control,Rule
}

type ScanInfo struct {
	UseExceptions             string   // Load file with exceptions configuration
	AuditExceptions           bool     // Include exception usage audit in supported scan outputs
	ControlsInputs            string   // Load file with inputs for controls
	AttackTracks              string   // Load file with attack tracks
	UseFrom                   []string // Load framework from local file (instead of download). Use when running offline
	UseDefault                bool     // Load framework from cached file (instead of download). Use when running offline
	UseArtifactsFrom          string   // Load artifacts from local path. Use when running offline
	ControlsVersion           string   // Pin the regolibrary release used to download policies (e.g. "v2.0.301"). Empty uses the latest release
	VerboseMode               bool     // Display all the input resources and not only failed resources
	Hide                      bool     // Hide sensitive identifiers (names, namespaces, images) in results
	EncryptionEnabled         bool
	View                      string                       //
	Format                    string                       // Format results (table, json, junit ...)
	Output                    string                       // Store results in an output file, Output file name
	FormatVersion             string                       // Output object can be different between versions, this is for testing and backward compatibility
	CustomClusterName         string                       // Set the custom name of the cluster
	ExcludedNamespaces        string                       // used for host scanner namespace
	IncludeNamespaces         string                       //
	IncludeKinds              string                       // comma-separated Kubernetes kinds to include (case-insensitive, Kind name only); e.g. "Deployment,DaemonSet"
	ExcludeKinds              string                       // comma-separated Kubernetes kinds to exclude (case-insensitive, Kind name only); e.g. "Job,CronJob"
	LabelSelector             string                       // filter collected resources by Kubernetes label selector (e.g. "app=nginx,env!=dev")
	Namespace                 string                       // target namespace for workload scans
	InputPatterns             []string                     // Yaml files input patterns
	Silent                    bool                         // Silent mode - Do not print progress logs
	FailThreshold             float32                      // DEPRECATED - Failure score threshold
	ComplianceThreshold       float32                      // Compliance score threshold
	FailThresholdSeverity     string                       // Severity at and above which the command should fail
	OnlyFixable               bool                         // Gate the severity threshold to only count CVEs that have an available fix
	FailCoverageThreshold     float32                      // Coverage threshold below which the command fails (0 = disabled)
	FailOnDegradedConfig      bool                         // Fail the scan if control inputs or exceptions could not be loaded and a fallback was used
	Submit                    BoolPtrFlag                  // Submit results to Kubescape Cloud BE. Get() is nil unless explicitly set by the caller (flag/env/request field)
	ScanID                    string                       // Report id of the current scan
	HostSensorEnabled         BoolPtrFlag                  // Deploy Kubescape K8s host scanner to collect data from certain controls
	HostSensorYamlPath        string                       // Path to hostsensor file
	Local                     bool                         // Do not submit results
	AccountID                 string                       // account ID
	AccessKey                 string                       // access key
	FrameworkScan             bool                         // false if scanning control
	ScanAll                   bool                         // true if scan all frameworks
	OmitRawResources          bool                         // true if omit raw resources from the output
	ShowEvidence              bool                         // Show evidence paths with current field values in pretty-printer output (-E / --show-evidence)
	ShowSecrets               bool                         // Show secret field values in evidence output; redacted by default (--show-secrets)
	PrintAttackTree           bool                         // true if print attack tree
	EnableRegoPrint           bool                         // true if print rego
	ScanObject                *objectsenvelopes.ScanObject // identifies a single resource (k8s object) to be scanned
	IsDeletedScanObject       bool                         // indicates whether the ScanObject is a deleted K8S resource
	TriggeredByCLI            bool                         // indicates whether the scan was triggered by the CLI
	ScanType                  ScanTypes
	ScanImages                bool
	UseDefaultMatchers        bool
	ScanTimeout               time.Duration // Maximum duration for the entire scan (0 = no timeout)
	ControlTimeout            time.Duration // Maximum duration for evaluating a single control (0 = no timeout)
	EnableStreaming           bool          // Enable resource streaming for large clusters to keep the evaluation input bounded
	DryRun                    bool          // Check RBAC access for the resources the scan would need, without collecting or evaluating anything
	ChartPath                 string
	FilePath                  string
	HelmValueFiles            []string // -f / --values: paths to Helm values YAML files (repeatable)
	HelmSetValues             []string // --set: Helm value overrides as key=value (repeatable)
	HelmSetStringValues       []string // --set-string: forced-string Helm value overrides
	HelmSetFileValues         []string // --set-file: Helm value overrides whose value is read from a file
	HelmReleaseName           string   // --release-name: Helm release name made available as .Release.Name during render
	HelmReleaseNamespace      string   // --release-namespace: Helm release namespace made available as .Release.Namespace
	LabelsToCopy              []string // Labels to copy from workloads to scan reports
	scanningContext           *ScanningContext
	kubeconfigPath            string
	kubeContextOverride       string
	clusterContextName        string
	contextResolved           bool
	cleanups                  []func()
	ListingURL                string            //Grype vulnerability database URL
	RegistryMapping           map[string]string // Map internal registry URLs to external ones
	RegistryAuthority         string            // Registry host[:port] explicit credentials apply to
	RegistryUsername          string            // Username for workload image registry authentication
	RegistryPassword          string            // Password for workload image registry authentication
	RegistryToken             string            // Bearer token for workload image registry authentication
	ImageScanConcurrency      int               // Number of concurrent workers for image scanning
	ImagePlatform             string            // OCI platform used for image scanning (os/architecture[/variant])
	MinSeverity               string            // Only include controls at or above this severity in the output
	MaxSeverity               string            // Only include controls at or below this severity in the output
	Baseline                  string            // Path to a saved JSON scan report; when set, the fresh scan is diffed against it
	BaselineFailOnNew         bool              // Exit with code 1 when the baseline diff finds new or incomparable failures
	BaselineSeverityThreshold string            // Only count new/incomparable baseline failures at or above this severity when enforcing BaselineFailOnNew
	BaselineGranularity       string            // Comparison unit for the baseline diff: "evidence" (default) or "control"
	OtelEndpoint              string            // OTLP endpoint (host:port, e.g. "localhost:4317") to export scan traces/metrics to via gRPC. Falls back to OTEL_EXPORTER_OTLP_ENDPOINT when empty. Empty means OTel export is disabled
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
	AttackTracksGetter   getter.IAttackTracksGetter
}

func (scanInfo *ScanInfo) Init(ctx context.Context, policyIdentifiers []PolicyIdentifier) error {
	scanInfo.setUseFrom(policyIdentifiers)
	if err := scanInfo.setUseArtifactsFrom(ctx); err != nil {
		return err
	}
	// setUseFrom and setUseArtifactsFrom can resolve to the same file - --use-default and
	// --use-artifacts-from both point at the local store on the offline HTTP handler path -
	// and a repeated path costs an extra read and unmarshal per policy load.
	scanInfo.UseFrom = unique(scanInfo.UseFrom)
	if scanInfo.ScanID == "" {
		scanInfo.ScanID = uuid.NewString()
	}
	return nil
}

func (scanInfo *ScanInfo) Cleanup() {
	for _, cleanup := range scanInfo.cleanups {
		cleanup()
	}
}

func (scanInfo *ScanInfo) AddCleanup(cleanup func()) {
	scanInfo.cleanups = append(scanInfo.cleanups, cleanup)
}

func (scanInfo *ScanInfo) setUseArtifactsFrom(ctx context.Context) error {
	if scanInfo.UseArtifactsFrom == "" {
		return nil
	}
	// UseArtifactsFrom must be a directory. If it points at a single file,
	// fall back to its parent directory based on the filesystem, not a name
	// heuristic (a directory named "*.json" is still a directory). A bare
	// filename with no path separator is left untouched so os.ReadDir below
	// surfaces the existing clear error instead of silently scanning ".".
	// An explicit current-directory path like "./<file>" has a separator, so
	// it falls back to "." as its parent directory.
	if info, err := os.Stat(scanInfo.UseArtifactsFrom); err == nil && !info.IsDir() {
		if filepath.Base(scanInfo.UseArtifactsFrom) != scanInfo.UseArtifactsFrom {
			scanInfo.UseArtifactsFrom = filepath.Dir(scanInfo.UseArtifactsFrom)
		}
	}
	// set frameworks files
	files, err := os.ReadDir(scanInfo.UseArtifactsFrom)
	if err != nil {
		return fmt.Errorf("failed to read files from directory %q: %w", scanInfo.UseArtifactsFrom, err)
	}
	framework := &reporthandling.Framework{}
	for _, f := range files {
		filePath := filepath.Join(scanInfo.UseArtifactsFrom, f.Name())
		file, err := os.ReadFile(filepath.Clean(filePath))
		if err == nil {
			if err := json.Unmarshal(file, framework); err == nil {
				scanInfo.UseFrom = append(scanInfo.UseFrom, filepath.Join(scanInfo.UseArtifactsFrom, f.Name()))
			}
		}
	}
	// set config-inputs file
	if scanInfo.ControlsInputs == "" {
		scanInfo.ControlsInputs = filepath.Join(scanInfo.UseArtifactsFrom, LocalControlInputsFilename)
	}
	// set exceptions
	if scanInfo.UseExceptions == "" {
		scanInfo.UseExceptions = filepath.Join(scanInfo.UseArtifactsFrom, LocalExceptionsFilename)
	}

	// set attack tracks
	if scanInfo.AttackTracks == "" {
		scanInfo.AttackTracks = filepath.Join(scanInfo.UseArtifactsFrom, LocalAttackTracksFilename)
	}
	return nil
}

func (scanInfo *ScanInfo) setUseFrom(policyIdentifiers []PolicyIdentifier) {
	if scanInfo.UseDefault {
		for _, policy := range policyIdentifiers {
			path, err := getter.PolicyCachePath(policy.Identifier)
			if err != nil {
				logger.L().Warning("skipping default cache lookup for policy", helpers.String("identifier", policy.Identifier), helpers.Error(err))
				continue
			}
			scanInfo.UseFrom = append(scanInfo.UseFrom, path)
		}
	}
}

// Formats returns a slice of output formats that have been requested for a given scan.
// Empty entries and surrounding whitespace are dropped so that inputs like
// "json,,pdf" or "json, ,pdf" do not produce blank format strings.
func (scanInfo *ScanInfo) Formats() []string {
	if scanInfo.Format == "" {
		return []string{}
	}

	var cleaned []string
	for f := range strings.SplitSeq(scanInfo.Format, ",") {
		if v := strings.TrimSpace(f); v != "" {
			cleaned = append(cleaned, v)
		}
	}

	return unique(cleaned)
}

func unique(items []string) []string {
	seen := map[string]bool{}
	result := []string{}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func (scanInfo *ScanInfo) SetScanType(scanType ScanTypes) {
	scanInfo.ScanType = scanType
}

// BuildPolicyIdentifiers builds a list of policy identifiers from the given
// string identifiers, adding any new ones that are not already present.
func BuildPolicyIdentifiers(policies []string, kind apisv1.NotificationPolicyKind) []PolicyIdentifier {
	return AppendPolicyIdentifiers(nil, policies, kind)
}

// AppendPolicyIdentifiers appends the given string identifiers to the existing
// list, adding any new ones that are not already present.
func AppendPolicyIdentifiers(existing []PolicyIdentifier, policies []string, kind apisv1.NotificationPolicyKind) []PolicyIdentifier {
	result := append([]PolicyIdentifier(nil), existing...)
	for _, policy := range policies {
		if !containsIdentifier(result, policy) {
			result = append(result, PolicyIdentifier{
				Kind:       kind,
				Identifier: policy,
			})
		}
	}
	return result
}

// containsIdentifier reports whether the named identifier is already present.
// The comparison is case-insensitive because a cache round-trip changes the casing:
// the downloader lists regolibrary's lower case "nsa" and writes a file whose name
// field is "NSA", so LoadPolicy.ListFrameworks reads back a name that no longer matches
// the lower case getter.NativeFrameworks entry. Matching exactly would leave both in the
// list and make downloadScanPolicies fetch and evaluate the same framework twice.
func containsIdentifier(identifiers []PolicyIdentifier, name string) bool {
	for _, policy := range identifiers {
		if strings.EqualFold(policy.Identifier, name) {
			return true
		}
	}
	return false
}

// splitNamespaceList parses a comma-separated namespace list (as accepted by
// --exclude-namespaces / --include-namespaces) into a clean slice. Empty
// entries and surrounding whitespace are dropped.
func splitNamespaceList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func scanInfoToScanMetadata(ctx context.Context, scanInfo *ScanInfo, policyIdentifiers []PolicyIdentifier) *reporthandlingv2.Metadata {
	metadata := &reporthandlingv2.Metadata{}

	metadata.ScanMetadata.Formats = scanInfo.Formats()
	metadata.ScanMetadata.FormatVersion = scanInfo.FormatVersion
	metadata.ScanMetadata.Submit = scanInfo.Submit.GetBool()

	if ns := splitNamespaceList(scanInfo.ExcludedNamespaces); len(ns) > 0 {
		metadata.ScanMetadata.ExcludedNamespaces = ns
	}
	if ns := splitNamespaceList(scanInfo.IncludeNamespaces); len(ns) > 0 {
		metadata.ScanMetadata.IncludeNamespaces = ns
	}

	// scan type
	if len(policyIdentifiers) > 0 {
		metadata.ScanMetadata.TargetType = string(policyIdentifiers[0].Kind)
	}
	// append frameworks
	for _, policy := range policyIdentifiers {
		metadata.ScanMetadata.TargetNames = append(metadata.ScanMetadata.TargetNames, policy.Identifier)
	}

	metadata.ScanMetadata.KubescapeVersion = versioncheck.BuildNumber
	metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	metadata.ScanMetadata.FailThreshold = scanInfo.FailThreshold
	metadata.ScanMetadata.ComplianceThreshold = scanInfo.ComplianceThreshold
	metadata.ScanMetadata.HostScanner = scanInfo.HostSensorEnabled.GetBool()
	metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	metadata.ScanMetadata.ControlsInputs = scanInfo.ControlsInputs

	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		// cluster
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
	case ContextFile:
		// local file
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
	case ContextGitLocal:
		// local-git
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.GitLocal
	case ContextGitRemote:
		// remote
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Repo
	case ContextDir:
		// directory
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory

	}

	scanInfo.setContextMetadata(ctx, &metadata.ContextMetadata)

	return metadata
}

func (scanInfo *ScanInfo) GetInputFiles() string {
	if len(scanInfo.InputPatterns) > 0 {
		return scanInfo.InputPatterns[0]
	}
	return ""
}

func (scanInfo *ScanInfo) GetScanningContext() ScanningContext {
	if scanInfo.scanningContext == nil {
		input := scanInfo.GetInputFiles()
		scanningContext := scanInfo.getScanningContext(input)
		if input != "" {
			scanInfo.cloneAdditionalRemoteInputs(input)
		}
		scanInfo.scanningContext = &scanningContext
	}
	return *scanInfo.scanningContext
}

// SetKubeconfigSelection records the CLI kubeconfig selection without loading
// it. Loading is deferred until Kubescape knows that the target is a live
// cluster, so an irrelevant kubeconfig cannot break an offline manifest scan.
func (scanInfo *ScanInfo) SetKubeconfigSelection(path, contextName string) {
	scanInfo.kubeconfigPath = path
	scanInfo.kubeContextOverride = contextName
	scanInfo.clusterContextName = ""
	scanInfo.contextResolved = false
}

// ResolveClusterContextName resolves the context from the same kubeconfig
// loading rules selected for the Kubernetes REST client. When neither an
// explicit path nor a context override is configured, the existing
// k8s-interface loading and in-cluster behavior is retained.
func (scanInfo *ScanInfo) ResolveClusterContextName() error {
	if scanInfo.kubeconfigPath == "" && scanInfo.kubeContextOverride == "" {
		return nil
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if scanInfo.kubeconfigPath != "" {
		loadingRules.ExplicitPath = scanInfo.kubeconfigPath
	}

	kubeconfig, err := loadingRules.Load()
	if err != nil {
		if scanInfo.kubeconfigPath != "" {
			return fmt.Errorf("failed to load kubeconfig %q: %w", scanInfo.kubeconfigPath, err)
		}
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	contextName := kubeconfig.CurrentContext
	if scanInfo.kubeContextOverride != "" {
		contextName = scanInfo.kubeContextOverride
	}
	if _, ok := kubeconfig.Contexts[contextName]; !ok {
		if scanInfo.kubeconfigPath != "" {
			return fmt.Errorf("context %q does not exist in kubeconfig %q", contextName, scanInfo.kubeconfigPath)
		}
		return fmt.Errorf("context %q does not exist in kubeconfig", contextName)
	}

	scanInfo.clusterContextName = contextName
	scanInfo.contextResolved = true
	return nil
}

// GetClusterContextName returns the context resolved from the CLI kubeconfig
// and context selection, falling back to k8s-interface when neither was
// resolved by this scan.
func (scanInfo *ScanInfo) GetClusterContextName() string {
	if scanInfo.contextResolved {
		return scanInfo.clusterContextName
	}
	return k8sinterface.GetContextName()
}

// getScanningContext get scanning context from the input param
// this function should be called only once. Call GetScanningContext() to get the scanning context
func (scanInfo *ScanInfo) getScanningContext(input string) ScanningContext {
	//  cluster
	if input == "" {
		return ContextCluster
	}

	// Check if input is a URL (http:// or https://)
	isURL := isHTTPURL(input)

	// git url
	if _, err := giturl.NewGitURL(input); err == nil {
		originalInput := input
		if repo, err := CloneGitRepo(&input); err == nil {
			if _, err := NewLocalGitRepository(repo); err == nil {
				scanInfo.AddCleanup(func() {
					if err := ReleaseClonedRepo(originalInput); err != nil {
						logger.L().Warning("failed to clean up cloned repository", helpers.String("url", originalInput), helpers.Error(err))
					}
				})
				return ContextGitRemote
			}
			if err := ReleaseClonedRepo(originalInput); err != nil {
				logger.L().Warning("failed to clean up invalid cloned repository", helpers.String("url", originalInput), helpers.Error(err))
			}
		}
		// If giturl.NewGitURL succeeded but cloning failed, the input is a git URL
		// that couldn't be cloned. Don't treat it as a local path.
		// The clone error was already logged by CloneGitRepo.
		// Return ContextDir to prevent the URL from being joined with the current directory
		// and to trigger a "no files found" error with the actual URL (not a mangled path).
		return ContextDir
	}

	// If it looks like a URL but wasn't recognized as a git URL, still don't treat it as a local path
	if isURL {
		logger.L().Error("URL provided but not recognized as a valid git repository. Ensure the URL is correct and accessible", helpers.String("url", input))
		return ContextDir
	}

	if !filepath.IsAbs(input) { // parse path
		if o, err := os.Getwd(); err == nil {
			input = filepath.Join(o, input)
		}
	}

	// local git repo
	if _, err := NewLocalGitRepository(input); err == nil {
		return ContextGitLocal
	}

	//  single file
	if isFile(input) {
		return ContextFile
	}

	//  dir/glob
	return ContextDir
}

// cloneAdditionalRemoteInputs prepares every remote input before file loading.
// Previously only the first URL was cloned, so later URL inputs were interpreted
// as local filesystem paths and silently skipped.
func (scanInfo *ScanInfo) cloneAdditionalRemoteInputs(firstInput string) {
	for _, candidate := range scanInfo.InputPatterns {
		if candidate == firstInput {
			continue
		}
		if _, err := giturl.NewGitURL(candidate); err != nil {
			continue
		}

		originalInput := candidate
		if _, err := CloneGitRepo(&candidate); err != nil {
			logger.L().Error("failed to clone additional git input", helpers.String("url", originalInput), helpers.Error(err))
			continue
		}
		scanInfo.AddCleanup(func() {
			if err := ReleaseClonedRepo(originalInput); err != nil {
				logger.L().Warning("failed to clean up cloned repository", helpers.String("url", originalInput), helpers.Error(err))
			}
		})
	}
}

func (scanInfo *ScanInfo) setContextMetadata(ctx context.Context, contextMetadata *reporthandlingv2.ContextMetadata) {
	input := scanInfo.GetInputFiles()
	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		contextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			ContextName: scanInfo.GetClusterContextName(),
		}
	case ContextDir:
		// the base path must be the root the file loader anchored the resources'
		// relative paths on, or the two no longer compose for anyone joining them
		basePath := ScanRootPath(input)
		contextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{
			BasePath: basePath,
			HostName: getHostname(),
		}
		// add repo context for submitting
		contextMetadata.RepoContextMetadata = &reporthandlingv2.RepoContextMetadata{
			Provider:      "none",
			Repo:          fmt.Sprintf("path@%s", getAbsPath(input)),
			Owner:         getHostname(),
			Branch:        "none",
			DefaultBranch: "none",
			LocalRootPath: basePath,
		}

	case ContextFile:
		contextMetadata.FileContextMetadata = &reporthandlingv2.FileContextMetadata{
			FilePath: getAbsPath(input),
			HostName: getHostname(),
		}
		// add repo context for submitting
		contextMetadata.RepoContextMetadata = &reporthandlingv2.RepoContextMetadata{
			Provider:      "none",
			Repo:          fmt.Sprintf("file@%s", getAbsPath(input)),
			Owner:         getHostname(),
			Branch:        "none",
			DefaultBranch: "none",
			LocalRootPath: ScanRootPath(input),
		}
	case ContextGitLocal:
		// local
		repoContext, err := metadataGitLocal(input)
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitLocal), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = repoContext
	case ContextGitRemote:
		// remote
		repoContext, err := metadataGitLocal(GetClonedPath(input))
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitRemote), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = repoContext
	}
}

func metadataGitLocal(input string) (*reporthandlingv2.RepoContextMetadata, error) {
	repoContext := &reporthandlingv2.RepoContextMetadata{
		Branch:        "none",
		DefaultBranch: "none",
		LocalRootPath: getAbsPath(input),
	}
	gitParser, err := NewLocalGitRepository(input)
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	if root, rootErr := gitParser.GetRootDir(); rootErr == nil {
		repoContext.LocalRootPath = root
	}
	remoteURL, err := gitParser.GetRemoteUrl()
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	gitParserURL, err := giturl.NewGitURL(remoteURL)
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	branchName := gitParser.GetBranchName()
	if branchName != "" {
		gitParserURL.SetBranchName(branchName)
		repoContext.Branch = branchName
		repoContext.DefaultBranch = ""
	}

	repoContext.Provider = gitParserURL.GetProvider()
	repoContext.Repo = gitParserURL.GetRepoName()
	repoContext.Owner = gitParserURL.GetOwnerName()
	repoContext.RemoteURL = gitParserURL.GetURL().String()

	commit, err := gitParser.GetLastCommit()
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	repoContext.LastCommit = reporthandling.LastCommit{
		Hash:          commit.SHA,
		Date:          commit.Committer.Date,
		CommitterName: commit.Committer.Name,
	}
	return repoContext, nil
}
func getHostname() string {
	if h, e := os.Hostname(); e == nil {
		return h
	}
	return ""
}

func getAbsPath(p string) string {
	if !filepath.IsAbs(p) { // parse path
		if o, err := os.Getwd(); err == nil {
			return filepath.Join(o, p)
		}
	}
	return p
}

// isHTTPURL checks if the input string is an HTTP or HTTPS URL
func isHTTPURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}
KSEOF_UNIQUE_9f3a

cat > core/pkg/resultshandling/results.go << 'KSEOF_UNIQUE_9f3a'
package resultshandling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	printerv1 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v1"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v4/core/pkg/vapreconcile"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ResultsHandler struct {
	ReporterObj   reporter.IReport
	UiPrinter     printer.IPrinter
	ScanData      *cautils.OPASessionObj
	PrinterObjs   []printer.IPrinter
	ImageScanData []cautils.ImageScanData
	scanError     error
}

func NewResultsHandler(reporterObj reporter.IReport, printerObjs []printer.IPrinter, uiPrinter printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		ReporterObj:   reporterObj,
		PrinterObjs:   printerObjs,
		UiPrinter:     uiPrinter,
		ImageScanData: make([]cautils.ImageScanData, 0),
	}
}

// GetRiskScore returns the result’s risk score
func (rh *ResultsHandler) GetRiskScore() float32 {
	return rh.ScanData.Report.SummaryDetails.Score
}

// GetComplianceScore returns the result’s compliance score
func (rh *ResultsHandler) GetComplianceScore() float32 {
	return rh.ScanData.Report.SummaryDetails.ComplianceScore
}

// GetData returns scan/action related data (policies, resources, results, etc.)
//
// Call the ToJson() method if you want the JSON representation of the data
func (rh *ResultsHandler) GetData() *cautils.OPASessionObj {
	return rh.ScanData
}

// SetData sets the scan/action related data
func (rh *ResultsHandler) SetData(data *cautils.OPASessionObj) {
	rh.ScanData = data
}

// SetScanError records a scan error that must be returned after any partial
// results have been printed. This lets callers preserve useful scan output
// without reporting a successful exit status for incomplete results.
func (rh *ResultsHandler) SetScanError(err error) {
	rh.scanError = err
}

// GetPrinters returns all printers
func (rh *ResultsHandler) GetPrinters() []printer.IPrinter {
	return rh.PrinterObjs
}

// GetReporter returns the reporter object
func (rh *ResultsHandler) GetReporter() reporter.IReport {
	return rh.ReporterObj
}

// ToJson returns the results in the JSON format
func (rh *ResultsHandler) ToJson() ([]byte, error) {
	finalizedReport := printerv2.FinalizeResults(rh.ScanData)
	enrichedReport := printerv2.ConvertToPostureReportWithSeverityLabelsAndCoverage(
		finalizedReport,
		rh.ScanData.LabelsToCopy,
		rh.ScanData.AllResources,
		&rh.ScanData.ScanCoverage,
	)

	// Keep the established programmatic JSON contract and override only the two
	// control collections for which the output printers derive severity.
	// Marshaling PostureReportWithSeverity directly would omit legacy top-level
	// fields, rawResource, and nanoseconds from generationTime.
	type summaryWithEnrichment struct {
		reportsummary.SummaryDetails
		Controls map[string]printerv2.ControlSummaryWithSeverity `json:"controls,omitempty"`
	}
	type resultWithEnrichment struct {
		resourcesresults.Result
		AssociatedControls []printerv2.ResourceAssociatedControlWithSeverity `json:"controls,omitempty"`
	}

	results := make([]resultWithEnrichment, len(finalizedReport.Results))
	for i := range finalizedReport.Results {
		results[i] = resultWithEnrichment{
			Result:             finalizedReport.Results[i],
			AssociatedControls: enrichedReport.Results[i].AssociatedControls,
		}
	}

	output := struct {
		*reporthandlingv2.PostureReport
		SummaryDetails summaryWithEnrichment        `json:"summaryDetails,omitempty"`
		Results        []resultWithEnrichment       `json:"results,omitempty"`
		ResourceLabels map[string]map[string]string `json:"resourceLabels,omitempty"`
		ScanCoverage   *cautils.ScanCoverage        `json:"scanCoverage,omitempty"`
		ExceptionAudit *cautils.ExceptionAudit      `json:"exceptionAudit,omitempty"`
	}{
		PostureReport: finalizedReport,
		SummaryDetails: summaryWithEnrichment{
			SummaryDetails: finalizedReport.SummaryDetails,
			Controls:       enrichedReport.SummaryDetails.Controls,
		},
		Results:        results,
		ResourceLabels: enrichedReport.ResourceLabels,
		ScanCoverage:   enrichedReport.ScanCoverage,
		ExceptionAudit: rh.ScanData.ExceptionAudit,
	}

	return json.Marshal(&output)
}

// GetResults returns the results
func (rh *ResultsHandler) GetResults() *reporthandlingv2.PostureReport {
	return printerv2.FinalizeResults(rh.ScanData)
}

// reportSnapshot holds the parts of ScanData that ApplySeverityFilters mutates
// in place, so HandleResults can restore them after printers and submission
// have run.
type reportSnapshot struct {
	controls map[string]reportsummary.ControlSummary
	// Per-resource copies of AssociatedControls, keyed like ScanData.ResourcesResult.
	associatedControls map[string][]resourcesresults.ResourceAssociatedControl
}

func snapshotReport(sessionObj *cautils.OPASessionObj) reportSnapshot {
	if sessionObj == nil || sessionObj.Report == nil {
		return reportSnapshot{}
	}

	src := sessionObj.Report.SummaryDetails.Controls
	controls := make(map[string]reportsummary.ControlSummary, len(src))
	for k, v := range src {
		controls[k] = v
	}

	ac := make(map[string][]resourcesresults.ResourceAssociatedControl, len(sessionObj.ResourcesResult))
	for id, r := range sessionObj.ResourcesResult {
		copy_ := make([]resourcesresults.ResourceAssociatedControl, len(r.AssociatedControls))
		copy(copy_, r.AssociatedControls)
		ac[id] = copy_
	}

	return reportSnapshot{controls: controls, associatedControls: ac}
}

func restoreReport(sessionObj *cautils.OPASessionObj, snap reportSnapshot) {
	if sessionObj == nil || sessionObj.Report == nil {
		return
	}
	sessionObj.Report.SummaryDetails.Controls = snap.controls
	for id, ac := range snap.associatedControls {
		if result, ok := sessionObj.ResourcesResult[id]; ok {
			result.AssociatedControls = ac
			sessionObj.ResourcesResult[id] = result
		}
	}
}

// HandleResults handles all necessary actions for the scan results
func (rh *ResultsHandler) HandleResults(ctx context.Context, scanInfo *cautils.ScanInfo) error {
	if rh.ScanData != nil && len(rh.ScanData.VAPPolicies) > 0 {
		index := vapreconcile.BuildIndex(rh.ScanData.VAPPolicies, rh.ScanData.VAPBindings)
		vapreconcile.EnrichSummary(rh.ScanData.Report.SummaryDetails.Controls, index)
	}

	// Snapshot both Report.SummaryDetails.Controls and every
	// ResourcesResult[id].AssociatedControls before applying severity filters.
	// ApplySeverityFilters mutates both in place; printers and submission see
	// the narrowed set, but the caller (cmd/scan) evaluates exit thresholds
	// and coverage counts after HandleResults returns and must see the full
	// unfiltered report. Other consumers of rh.ScanData (httphandler /v1/results,
	// StorePostureReportResults) also read the report after this call and
	// must not receive an internally inconsistent PostureReport.
	snap := snapshotReport(rh.ScanData)
	defer restoreReport(rh.ScanData, snap)
	ApplySeverityFilters(rh.ScanData, scanInfo.MinSeverity, scanInfo.MaxSeverity)

	// Display scan results in the UI first to give immediate value.
	var printErr error

	if err := rh.UiPrinter.ActionPrint(ctx, rh.ScanData, rh.ImageScanData); err != nil {
		printErr = errors.Join(printErr, fmt.Errorf("ui printer: %w", err))
	}

	rh.UiPrinter.PrintNextSteps()
	if err := closePrinter(rh.UiPrinter); err != nil {
		printErr = errors.Join(printErr, fmt.Errorf("ui printer close: %w", err))
	}

	// Then print to output files
	for _, p := range rh.PrinterObjs {
		if err := p.ActionPrint(ctx, rh.ScanData, rh.ImageScanData); err != nil {
			printErr = errors.Join(printErr, fmt.Errorf("output printer %T: %w", p, err))
		}
		if rh.ScanData != nil {
			p.Score(rh.GetComplianceScore())
		}
		if err := closePrinter(p); err != nil {
			printErr = errors.Join(printErr, fmt.Errorf("output printer %T close: %w", p, err))
		}
	}

	if err := errors.Join(printErr, rh.scanError); err != nil {
		return err
	}

	// We should submit only after printing results, so a user can see
	// results at all times, even if submission fails
	if rh.ReporterObj != nil && scanInfo.Submit.GetBool() {
		if err := rh.ReporterObj.Submit(ctx, rh.ScanData); err != nil {
			return err
		}
		rh.ReporterObj.DisplayMessage()
	}

	return nil
}

// NewPrinter returns a new printer for a given format and configuration options
func NewPrinter(ctx context.Context, printFormat string, scanInfo *cautils.ScanInfo, clusterName string) printer.IPrinter {

	switch printFormat {
	case printer.JsonFormat:
		switch scanInfo.FormatVersion {
		case "v1":
			logger.L().Ctx(ctx).Warning("Deprecated format version", helpers.String("run", "--format-version=v2"))
			return printerv1.NewJsonPrinter()
		default:
			return printerv2.NewJsonPrinter()
		}
	case printer.YamlFormat:
		if scanInfo.FormatVersion == "v1" {
			logger.L().Ctx(ctx).Warning("Deprecated format version", helpers.String("run", "--format-version=v2"))
		}
		return printerv2.NewYamlPrinter()
	case printer.CsvFormat:
		return printerv2.NewCsvPrinter()
	case printer.MarkdownFormat:
		return printerv2.NewMarkdownPrinter()
	case printer.JunitResultFormat:
		return printerv2.NewJunitPrinter(scanInfo.VerboseMode)
	case printer.PrometheusFormat:
		return printerv2.NewPrometheusPrinter(scanInfo.VerboseMode)
	case printer.OtelFormat:
		return printerv2.NewOtelPrinter(scanInfo.VerboseMode)
	case printer.PdfFormat:
		return printerv2.NewPdfPrinter()
	case printer.HtmlFormat:
		return printerv2.NewHtmlPrinter()
	case printer.SARIFFormat:
		return printerv2.NewSARIFPrinter()
	case printer.GitLabSASTFormat:
		return printerv2.NewGitLabSASTPrinter()
	case printer.CycloneDXFormat:
		return printerv2.NewCycloneDXPrinter()
	case printer.SPDXFormat:
		return printerv2.NewSPDXPrinter()
	case printer.PolicyReportFormat:
		return printerv2.NewPolicyReportPrinter()
	default:
		if printFormat != printer.PrettyFormat {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("Invalid format \"%s\", default format \"pretty-printer\" is applied", printFormat))
		}
		return printerv2.NewPrettyPrinter(scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View), scanInfo.ScanType, scanInfo.InputPatterns, clusterName, scanInfo.ShowEvidence, scanInfo.ShowSecrets)
	}
}

func ValidatePrinter(scanType cautils.ScanTypes, scanContext cautils.ScanningContext, printFormat string) (bool, error) {
	if scanType == cautils.ScanTypeImage {
		if printFormat == printer.PrettyFormat {
			return true, nil
		}
		if slices.Contains(printer.ImageFormats, printFormat) {
			return false, nil
		}
		return false, fmt.Errorf("format \"%s\" is not supported for image scanning", printFormat)
	}
	if printFormat == printer.SARIFFormat || printFormat == printer.GitLabSASTFormat {
		// SARIF and GitLab SAST resolve file locations, so they only apply to local files
		switch scanContext {
		case cautils.ContextDir, cautils.ContextFile, cautils.ContextGitLocal, cautils.ContextGitRemote:
			return false, nil
		default:
			return false, fmt.Errorf("format \"%s\" is only supported when scanning local files", printFormat)
		}
	}
	if printFormat == printer.CycloneDXFormat || printFormat == printer.SPDXFormat {
		return false, fmt.Errorf("format \"%s\" is only supported for image scanning", printFormat)
	}

	switch printFormat {
	case printer.JsonFormat, printer.HtmlFormat, printer.JunitResultFormat, printer.PrometheusFormat, printer.PdfFormat, printer.YamlFormat, printer.CsvFormat, printer.MarkdownFormat, printer.PolicyReportFormat, printer.OtelFormat:
		return false, nil
	default:
		return true, nil
	}
}

// closePrinter closes p's output writer if p implements an optional close
// contract, returning any error so callers can surface incomplete writes.
// Printers migrated to return an error from CloseWriter are preferred; the
// legacy void contract is still supported for backwards compatibility.
func closePrinter(p printer.IPrinter) error {
	type errorCloser interface {
		CloseWriter() error
	}
	if c, ok := p.(errorCloser); ok {
		return c.CloseWriter()
	}
	type voidCloser interface {
		CloseWriter()
	}
	if c, ok := p.(voidCloser); ok {
		c.CloseWriter()
	}
	return nil
}
KSEOF_UNIQUE_9f3a

cat > core/pkg/resultshandling/printer/printresults.go << 'KSEOF_UNIQUE_9f3a'
package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

var INDENT = "   "

const (
	PrettyFormat       string = "pretty-printer"
	JsonFormat         string = "json"
	JunitResultFormat  string = "junit"
	PrometheusFormat   string = "prometheus"
	PdfFormat          string = "pdf"
	HtmlFormat         string = "html"
	SARIFFormat        string = "sarif"
	GitLabSASTFormat   string = "gitlab-sast"
	YamlFormat         string = "yaml"
	CsvFormat          string = "csv"
	MarkdownFormat     string = "markdown"
	CycloneDXFormat    string = "cyclonedx-json"
	SPDXFormat         string = "spdx-json"
	PolicyReportFormat string = "policyreport"
	OtelFormat         string = "otel"
)

// AllFormats lists every output format kubescape can emit.
var AllFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, YamlFormat, CsvFormat, MarkdownFormat, CycloneDXFormat, SPDXFormat, PolicyReportFormat, OtelFormat}

// ImageFormats lists formats whose printers support image-scan data. CSV is
// deliberately excluded: CsvPrinter.ActionPrint requires opaSessionObj and
// errors out on image scans (#2743) — a format must not be advertised as
// image-scan-capable unless its printer actually handles that path.
//
// CycloneDXFormat and SPDXFormat are the inverse: they encode the SBOM that
// only exists on image scans, so they are image-scan-only (see ValidatePrinter).
var ImageFormats = []string{PrettyFormat, JsonFormat, JunitResultFormat, PrometheusFormat, PdfFormat, HtmlFormat, SARIFFormat, GitLabSASTFormat, YamlFormat, CycloneDXFormat, SPDXFormat, OtelFormat}

const (
	JsonOutputExt         = ".json"
	JunitOutputExt        = ".xml"
	SARIFOutputExt        = ".sarif"
	HtmlOutputExt         = ".html"
	PdfOutputExt          = ".pdf"
	PrometheusOutputExt   = ".txt"
	PrettyOutputExt       = ".txt"
	YamlOutputExt         = ".yaml"
	CsvOutputExt          = ".csv"
	MarkdownOutputExt     = ".md"
	CycloneDXOutputExt    = ".cdx.json"
	SPDXOutputExt         = ".spdx.json"
	PolicyReportOutputExt = ".yaml"
	// OtelOutputExt is nominal only: the "otel" format never writes a file
	// (see OtelPrinter.SetWriter), it exports over OTLP instead. It is
	// listed here purely so FormatOutputExt stays total over AllFormats.
	OtelOutputExt = ".otel"
)

// HasOutputExt reports whether outputFile already ends with ext, compared
// case-insensitively. Every v2 printer's SetWriter previously re-implemented
// this check with a case-sensitive filepath.Ext(...) != ext comparison, so
// --output Report.JSON (or any differently-cased extension) failed the check
// in every one of them and silently doubled up: Report.JSON.json.
func HasOutputExt(outputFile, ext string) bool {
	if len(outputFile) < len(ext) {
		return false
	}
	return strings.EqualFold(outputFile[len(outputFile)-len(ext):], ext)
}

// FormatOutputExt maps a format to the extension its printer enforces in
// SetWriter. Callers resolving an --output path must read it from here rather
// than re-deriving it, so a format can never resolve to a path its printer
// does not write. Every entry in AllFormats is covered.
var FormatOutputExt = map[string]string{
	PrettyFormat:       PrettyOutputExt,
	JsonFormat:         JsonOutputExt,
	JunitResultFormat:  JunitOutputExt,
	PrometheusFormat:   PrometheusOutputExt,
	PdfFormat:          PdfOutputExt,
	HtmlFormat:         HtmlOutputExt,
	SARIFFormat:        SARIFOutputExt,
	GitLabSASTFormat:   JsonOutputExt,
	YamlFormat:         YamlOutputExt,
	CsvFormat:          CsvOutputExt,
	MarkdownFormat:     MarkdownOutputExt,
	CycloneDXFormat:    CycloneDXOutputExt,
	SPDXFormat:         SPDXOutputExt,
	PolicyReportFormat: PolicyReportOutputExt,
	OtelFormat:         OtelOutputExt,
}

type IPrinter interface {
	PrintNextSteps()
	ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error
	SetWriter(ctx context.Context, outputFile string) error
	Score(score float32)
}

// outputDirPerm restricts created output directories to the owner (rwx------
// would be too tight for shared setups, so this keeps group read/traverse),
// instead of os.ModePerm (0777, world-writable) which scan output/report
// directories have no reason to be.
const outputDirPerm = 0o750

func GetWriter(ctx context.Context, outputFile string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := os.Create(filepath.Clean(outputFile))
		if err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}

// GetWriterNoFallback opens an explicitly requested output path. Unlike the
// legacy helpers, it never redirects an error to stdout or a temporary file:
// callers can return the setup failure before a scan starts.
func GetWriterNoFallback(outputFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err != nil {
		return nil, fmt.Errorf("create output directory for %q: %w", outputFile, err)
	}
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("open output file %q: %w", outputFile, err)
	}
	return f, nil
}

// GetWriterNoStdoutFallback opens outputFile for writing for formats whose
// output (binary, markup) would corrupt a TTY if dumped to stdout. On any
// failure to open the requested file it falls back to a uniquely-named file
// under os.TempDir() using tempPattern (e.g. "kubescape-report-*.pdf"). If
// that fails it tries os.DevNull, then a pipe-based sink as a last resort.
// It never returns os.Stdout.
func GetWriterNoStdoutFallback(ctx context.Context, outputFile, tempPattern string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), outputDirPerm); err == nil {
			if f, err := os.Create(filepath.Clean(outputFile)); err == nil {
				return f
			} else {
				logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			}
		} else {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
		}
	}
	if tmp, err := os.CreateTemp("", tempPattern); err == nil {
		logger.L().Ctx(ctx).Warning("could not write to requested output path; falling back to temp file",
			helpers.String("filename", tmp.Name()))
		return tmp
	} else {
		logger.L().Ctx(ctx).Error(fmt.Sprintf("failed to create temp output file, reason: %s", err.Error()))
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// os.DevNull should always be openable; if not, fall back to a temp file
		// so we still return a writable, closable handle.
		if tmp, tmpErr := os.CreateTemp(".", tempPattern); tmpErr == nil {
			logger.L().Ctx(ctx).Warning("failed to open os.DevNull; falling back to temp file",
				helpers.String("filename", tmp.Name()))
			return tmp
		}
		r, w, pipeErr := os.Pipe()
		if pipeErr == nil {
			go func() {
				_, _ = io.Copy(io.Discard, r)
				_ = r.Close()
			}()
			return w
		}
		// Final fallback: return a non-nil file handle even if it is not writable.
		return os.NewFile(^uintptr(0), os.DevNull)
	}
	return devNull
}

func LogOutputFile(fileName string) {
	if fileName != os.Stdout.Name() && fileName != os.Stderr.Name() && fileName != os.DevNull {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}
}
KSEOF_UNIQUE_9f3a

echo "Files written."
