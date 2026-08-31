// Package telemetrytest provides an in-process OTLP/gRPC collector for tests
// that need to assert what Kubescape actually put on the wire, rather than what
// it built in memory.
//
// It deliberately does not import testing, so it stays usable from any package
// without pulling test flags into a build.
package telemetrytest

import (
	"context"
	"net"
	"sync"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
)

// Collector records everything exported to it and answers questions about it.
// All accessors are safe to call while exports are still arriving.
type Collector struct {
	collectortrace.UnimplementedTraceServiceServer

	server   *grpc.Server
	endpoint string

	mu                 sync.Mutex
	spans              []*tracepb.Span
	metrics            []*metricspb.Metric
	resourceAttributes []*commonpb.KeyValue
}

// Start listens on an ephemeral loopback port and serves the OTLP trace and
// metrics services. The caller must Close it.
func Start() (*Collector, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	collector := &Collector{
		server:   grpc.NewServer(),
		endpoint: listener.Addr().String(),
	}
	collectortrace.RegisterTraceServiceServer(collector.server, collector)
	collectormetrics.RegisterMetricsServiceServer(collector.server, metricsService{collector: collector})

	go func() {
		_ = collector.server.Serve(listener)
	}()

	return collector, nil
}

// Endpoint is the host:port to pass to --otel-endpoint.
func (c *Collector) Endpoint() string { return c.endpoint }

func (c *Collector) Close() { c.server.Stop() }

func (c *Collector) Export(_ context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, resourceSpans := range req.GetResourceSpans() {
		c.resourceAttributes = resourceSpans.GetResource().GetAttributes()
		for _, scopeSpans := range resourceSpans.GetScopeSpans() {
			c.spans = append(c.spans, scopeSpans.GetSpans()...)
		}
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

func (c *Collector) addMetrics(req *collectormetrics.ExportMetricsServiceRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, resourceMetrics := range req.GetResourceMetrics() {
		if len(c.resourceAttributes) == 0 {
			c.resourceAttributes = resourceMetrics.GetResource().GetAttributes()
		}
		for _, scopeMetrics := range resourceMetrics.GetScopeMetrics() {
			c.metrics = append(c.metrics, scopeMetrics.GetMetrics()...)
		}
	}
}

// SpanNames returns the name of every span received, in arrival order.
func (c *Collector) SpanNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	names := make([]string, 0, len(c.spans))
	for _, span := range c.spans {
		names = append(names, span.GetName())
	}
	return names
}

// RootSpanCount counts spans whose parent was never itself exported, which is
// how a trace with a single root is distinguished from several stray ones.
func (c *Collector) RootSpanCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	known := make(map[string]bool, len(c.spans))
	for _, span := range c.spans {
		known[string(span.GetSpanId())] = true
	}

	roots := 0
	for _, span := range c.spans {
		if !known[string(span.GetParentSpanId())] {
			roots++
		}
	}
	return roots
}

// MetricNames returns the distinct metric names received.
func (c *Collector) MetricNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	seen := map[string]bool{}
	names := []string{}
	for _, m := range c.metrics {
		if seen[m.GetName()] {
			continue
		}
		seen[m.GetName()] = true
		names = append(names, m.GetName())
	}
	return names
}

func (c *Collector) HasMetric(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.metrics {
		if m.GetName() == name {
			return true
		}
	}
	return false
}

// SumPoints totals the int64 data points of a counter whose attributes contain
// every pair in want. An empty want matches every point.
func (c *Collector) SumPoints(name string, want map[string]string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	var total int64
	for _, m := range c.metrics {
		if m.GetName() != name {
			continue
		}
		for _, point := range m.GetSum().GetDataPoints() {
			if attributesContain(point.GetAttributes(), want) {
				total += point.GetAsInt()
			}
		}
	}
	return total
}

// HistogramSum returns the recorded count and summed value of a histogram whose
// points match want, which is how a duration measurement is asserted.
func (c *Collector) HistogramSum(name string, want map[string]string) (uint64, float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var count uint64
	var sum float64
	for _, m := range c.metrics {
		if m.GetName() != name {
			continue
		}
		for _, point := range m.GetHistogram().GetDataPoints() {
			if attributesContain(point.GetAttributes(), want) {
				count += point.GetCount()
				sum += point.GetSum()
			}
		}
	}
	return count, sum
}

// ResourceAttribute returns a string-valued resource attribute, or "" when the
// exported resource did not carry it.
func (c *Collector) ResourceAttribute(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, attribute := range c.resourceAttributes {
		if attribute.GetKey() == key {
			return attribute.GetValue().GetStringValue()
		}
	}
	return ""
}

func attributesContain(attributes []*commonpb.KeyValue, want map[string]string) bool {
	for key, value := range want {
		found := false
		for _, attribute := range attributes {
			if attribute.GetKey() == key && attribute.GetValue().GetStringValue() == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// metricsService adapts the metrics service onto Collector, which already uses
// Export for traces.
type metricsService struct {
	collectormetrics.UnimplementedMetricsServiceServer
	collector *Collector
}

func (s metricsService) Export(_ context.Context, req *collectormetrics.ExportMetricsServiceRequest) (*collectormetrics.ExportMetricsServiceResponse, error) {
	s.collector.addMetrics(req)
	return &collectormetrics.ExportMetricsServiceResponse{}, nil
}
