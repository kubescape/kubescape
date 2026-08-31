package scan

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry/telemetrytest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

// contextKubescape implements only the context half of meta.IKubescape, which
// is all the telemetry wrapper touches.
type contextKubescape struct {
	meta.IKubescape
	ctx context.Context
}

func (k *contextKubescape) Context() context.Context {
	return k.ctx
}

func (k *contextKubescape) SetContext(ctx context.Context) {
	k.ctx = ctx
}

func newTestCommand(name string, run func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{Use: name, RunE: run}
	cmd.SetContext(context.Background())
	return cmd
}

func TestInstallTelemetryWrapsCommandAndSubcommands(t *testing.T) {
	scanCmd := newTestCommand("scan", func(*cobra.Command, []string) error { return nil })
	framework := newTestCommand("framework", func(*cobra.Command, []string) error { return nil })
	exempt := newTestCommand("validate-contract", func(*cobra.Command, []string) error { return nil })
	scanCmd.AddCommand(framework, exempt)

	originalScan := scanCmd.RunE
	originalFramework := framework.RunE
	originalExempt := exempt.RunE

	installTelemetry(scanCmd, &contextKubescape{ctx: context.Background()}, &cautils.ScanInfo{})

	assertRewrapped(t, originalScan, scanCmd.RunE, "scan")
	assertRewrapped(t, originalFramework, framework.RunE, "framework")
	// validate-contract runs no scan, so it keeps its own RunE.
	assert.Equal(t, funcAddress(originalExempt), funcAddress(exempt.RunE), "validate-contract should not be wrapped")
}

func TestInstallTelemetrySkipsCommandsWithoutRunE(t *testing.T) {
	scanCmd := newTestCommand("scan", func(*cobra.Command, []string) error { return nil })
	container := &cobra.Command{Use: "container"}
	scanCmd.AddCommand(container)

	require.NotPanics(t, func() {
		installTelemetry(scanCmd, &contextKubescape{ctx: context.Background()}, &cautils.ScanInfo{})
	})
	assert.Nil(t, container.RunE)
}

func TestWrapWithTelemetryDisabledRunsCommandUntouched(t *testing.T) {
	clearTelemetryEnvironment(t)

	ks := &contextKubescape{ctx: context.Background()}
	var observedCtx context.Context
	ran := false

	run := wrapWithTelemetry(func(cmd *cobra.Command, args []string) error {
		ran = true
		observedCtx = ks.Context()
		return nil
	}, ks, &cautils.ScanInfo{})

	require.NoError(t, run(newTestCommand("scan", nil), nil))
	assert.True(t, ran)
	assert.False(t, telemetry.Active())
	// No provider was installed, so no span context was published.
	assert.False(t, trace.SpanContextFromContext(observedCtx).IsValid())
}

func TestWrapWithTelemetryPropagatesRunError(t *testing.T) {
	clearTelemetryEnvironment(t)

	wantErr := errors.New("scan failed")
	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		return wantErr
	}, &contextKubescape{ctx: context.Background()}, &cautils.ScanInfo{})

	assert.ErrorIs(t, run(newTestCommand("scan", nil), nil), wantErr)
}

func TestWrapWithTelemetryRejectsInvalidEndpoint(t *testing.T) {
	clearTelemetryEnvironment(t)

	ran := false
	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		ran = true
		return nil
	}, &contextKubescape{ctx: context.Background()}, &cautils.ScanInfo{OtelEndpoint: "localhost"})

	err := run(newTestCommand("scan", nil), nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--otel-endpoint")
	assert.False(t, ran, "a malformed endpoint should be reported before the scan starts")
}

func TestWrapWithTelemetryPublishesRootSpanAndRestoresContext(t *testing.T) {
	clearTelemetryEnvironment(t)

	baseCtx := context.WithValue(context.Background(), testContextKey{}, "base")
	ks := &contextKubescape{ctx: baseCtx}
	scanInfo := &cautils.ScanInfo{OtelEndpoint: startCollectorEndpoint(t)}

	var spanCtx trace.SpanContext
	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		scanInfo.SetScanType(cautils.ScanTypeCluster)
		spanCtx = trace.SpanContextFromContext(ks.Context())
		assert.True(t, telemetry.Active())
		return nil
	}, ks, scanInfo)

	require.NoError(t, run(newTestCommand("scan", nil), nil))

	// The pipeline reads its context from ks, so the root span has to be
	// visible there for the phase spans to nest under it.
	assert.True(t, spanCtx.IsValid(), "root span was not published to the Kubescape context")
	assert.Equal(t, baseCtx, ks.Context(), "the original context should be restored")
	assert.False(t, telemetry.Active(), "providers should be shut down after the run")
}

// TestWrapWithTelemetryExportsScanDuration pins the one measurement no other
// call site can produce: buildScanOutcome deliberately leaves Duration unset
// because only the command wrapper knows when the scan started, so this is the
// assertion that keeps kubescape_scan_duration_seconds exported.
func TestWrapWithTelemetryExportsScanDuration(t *testing.T) {
	clearTelemetryEnvironment(t)

	collector, err := telemetrytest.Start()
	require.NoError(t, err)
	t.Cleanup(collector.Close)

	ks := &contextKubescape{ctx: context.Background()}
	scanInfo := &cautils.ScanInfo{OtelEndpoint: collector.Endpoint()}

	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		scanInfo.SetScanType(cautils.ScanTypeCluster)
		time.Sleep(10 * time.Millisecond)
		return nil
	}, ks, scanInfo)

	require.NoError(t, run(newTestCommand("scan", nil), nil))

	count, sum := collector.HistogramSum("kubescape_scan_duration_seconds", map[string]string{
		"kubescape.scan.target": string(cautils.ScanTypeCluster),
	})
	assert.Equal(t, uint64(1), count, "scan duration was not exported")
	assert.Positive(t, sum, "scan duration should record the elapsed time")

	assert.Contains(t, collector.SpanNames(), rootSpanName)
	assert.Equal(t, 1, collector.RootSpanCount())
}

// TestWrapWithTelemetryExportsNoDurationWhenDisabled is the default path.
func TestWrapWithTelemetryExportsNoDurationWhenDisabled(t *testing.T) {
	clearTelemetryEnvironment(t)

	collector, err := telemetrytest.Start()
	require.NoError(t, err)
	t.Cleanup(collector.Close)

	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		return nil
	}, &contextKubescape{ctx: context.Background()}, &cautils.ScanInfo{})

	require.NoError(t, run(newTestCommand("scan", nil), nil))

	assert.False(t, collector.HasMetric("kubescape_scan_duration_seconds"))
	assert.Empty(t, collector.SpanNames())
}

func TestWrapWithTelemetryFlushesAfterFailedScan(t *testing.T) {
	clearTelemetryEnvironment(t)

	wantErr := errors.New("threshold exceeded")
	ks := &contextKubescape{ctx: context.Background()}
	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		return wantErr
	}, ks, &cautils.ScanInfo{OtelEndpoint: startCollectorEndpoint(t)})

	err := run(newTestCommand("scan", nil), nil)

	// A non-zero exit still has to export: a failing scan is exactly the one
	// an operator wants a trace for.
	assert.ErrorIs(t, err, wantErr)
	assert.False(t, telemetry.Active())
}

func TestWrapWithTelemetryShutsDownOnPanic(t *testing.T) {
	clearTelemetryEnvironment(t)

	baseCtx := context.Background()
	ks := &contextKubescape{ctx: baseCtx}
	run := wrapWithTelemetry(func(*cobra.Command, []string) error {
		panic("boom")
	}, ks, &cautils.ScanInfo{OtelEndpoint: startCollectorEndpoint(t)})

	assert.PanicsWithValue(t, "boom", func() {
		_ = run(newTestCommand("scan", nil), nil)
	})

	// A panic must not leave the SDK providers installed as process globals.
	assert.False(t, telemetry.Active())
	assert.Equal(t, baseCtx, ks.Context())
}

func TestWrapWithTelemetryNestedInvocationReusesProviders(t *testing.T) {
	clearTelemetryEnvironment(t)

	ks := &contextKubescape{ctx: context.Background()}
	scanInfo := &cautils.ScanInfo{OtelEndpoint: startCollectorEndpoint(t)}

	var innerCtx context.Context
	inner := wrapWithTelemetry(func(*cobra.Command, []string) error {
		innerCtx = ks.Context()
		return nil
	}, ks, scanInfo)

	var outerCtx context.Context
	outer := wrapWithTelemetry(func(cmd *cobra.Command, args []string) error {
		outerCtx = ks.Context()
		return inner(cmd, args)
	}, ks, scanInfo)

	require.NoError(t, outer(newTestCommand("scan", nil), nil))

	// The bare `scan` command delegates to the framework scan. The inner call
	// must join the running trace instead of starting its own lifecycle.
	assert.Equal(t, outerCtx, innerCtx)
	assert.False(t, telemetry.Active())
}

type testContextKey struct{}

func clearTelemetryEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		telemetry.EnvEndpoint,
		telemetry.EnvTracesEndpoint,
		telemetry.EnvMetricsEndpoint,
		telemetry.EnvProtocol,
		telemetry.EnvInsecure,
		telemetry.EnvServiceName,
	} {
		t.Setenv(name, "")
	}
}

// startCollectorEndpoint returns the address of a gRPC server with no OTLP
// services registered. Exports fail fast and non-retryably, which keeps these
// lifecycle tests quick; delivery itself is covered in the telemetry package.
func startCollectorEndpoint(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)

	return listener.Addr().String()
}

func funcAddress(fn func(*cobra.Command, []string) error) uintptr {
	return reflect.ValueOf(fn).Pointer()
}

func assertRewrapped(t *testing.T, original, wrapped func(*cobra.Command, []string) error, name string) {
	t.Helper()
	assert.NotEqual(t, funcAddress(original), funcAddress(wrapped), "%s should be wrapped with the telemetry lifecycle", name)
}
