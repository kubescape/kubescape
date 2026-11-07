package telemetrytest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCollectorAccessorsWhileExportsArrive(t *testing.T) {
	collector := &Collector{}
	const (
		exporters = 8
		exports   = 25
	)

	var wg sync.WaitGroup
	for exporter := 0; exporter < exporters; exporter++ {
		wg.Add(1)
		go func(exporter int) {
			defer wg.Done()
			for i := 0; i < exports; i++ {
				spanID := []byte{byte(exporter + 1), byte(i + 1)}
				traceRequest := &collectortrace.ExportTraceServiceRequest{
					ResourceSpans: []*tracepb.ResourceSpans{
						{
							Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
								{
									Key: "service.name",
									Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
										StringValue: fmt.Sprintf("exporter-%d", exporter),
									}},
								},
							}},
							ScopeSpans: []*tracepb.ScopeSpans{{
								Spans: []*tracepb.Span{{
									Name:         fmt.Sprintf("span-%d", i),
									SpanId:       spanID,
									ParentSpanId: []byte{0},
								}},
							}},
						},
					},
				}
				_, err := collector.Export(context.Background(), traceRequest)
				if err != nil {
					t.Errorf("export trace: %v", err)
					return
				}
				metricRequest := &collectormetrics.ExportMetricsServiceRequest{
					ResourceMetrics: []*metricspb.ResourceMetrics{
						{
							ScopeMetrics: []*metricspb.ScopeMetrics{{
								Metrics: []*metricspb.Metric{{
									Name: "test.counter",
									Data: &metricspb.Metric_Sum{
										Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{
											{Value: &metricspb.NumberDataPoint_AsInt{AsInt: int64(i)}},
										}},
									},
								}, {
									Name: "test.histogram",
									Data: &metricspb.Metric_Histogram{
										Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{{
											Count: 1,
											Sum:   float64Ptr(float64(i)),
										}}},
									},
								}},
							}},
						},
					},
				}
				if _, err := (&metricsService{collector: collector}).Export(context.Background(), metricRequest); err != nil {
					t.Errorf("export metric: %v", err)
					return
				}
			}
		}(exporter)
	}

	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range exports {
				collector.SpanNames()
				collector.RootSpanCount()
				collector.MetricNames()
				collector.HasMetric("test.counter")
				collector.SumPoints("test.counter", nil)
				collector.HistogramSum("test.histogram", nil)
				collector.ResourceAttribute("service.name")
			}
		}()
	}
	wg.Wait()

	if got := len(collector.SpanNames()); got != exporters*exports {
		t.Fatalf("got %d spans, want %d", got, exporters*exports)
	}
	if !collector.HasMetric("test.counter") {
		t.Fatal("expected exported counter")
	}
	if count, sum := collector.HistogramSum("test.histogram", nil); count != exporters*exports || sum != 2400 {
		t.Fatalf("HistogramSum() = (%d, %f), want (%d, 2400)", count, sum, exporters*exports)
	}
	if got := collector.ResourceAttribute("service.name"); got == "" {
		t.Fatal("expected a resource service.name attribute")
	}
}

func TestResourceAttributeKeepsFirstNonEmptyExport(t *testing.T) {
	collector := &Collector{}
	_, err := collector.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "trace-service"}},
			}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	(&metricsService{collector: collector}).Export(context.Background(), &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "metric-service"}},
			}}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{
					Name: "test.histogram",
					Data: &metricspb.Metric_Histogram{
						Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{{
							Count: 1,
							Sum:   float64Ptr(1.5),
						}}},
					},
				}},
			}},
		}},
	})
	_, err = collector.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "later-service"}},
			}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := collector.ResourceAttribute("service.name"); got != "trace-service" {
		t.Fatalf("service.name = %q, want first non-empty export value", got)
	}
}

func TestReset(t *testing.T) {
	collector := &Collector{}
	_, err := collector.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
					StringValue: "test-service",
				}},
			}}},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "span"}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	collector.Reset()

	if got := collector.SpanNames(); len(got) != 0 {
		t.Fatalf("SpanNames() = %v after reset", got)
	}
	if got := collector.MetricNames(); len(got) != 0 {
		t.Fatalf("MetricNames() = %v after reset", got)
	}
	if collector.HasMetric("test.counter") {
		t.Fatal("HasMetric() returned true after reset")
	}
	if got := collector.ResourceAttribute("service.name"); got != "" {
		t.Fatalf("ResourceAttribute() = %q after reset", got)
	}
}

func float64Ptr(value float64) *float64 { return &value }

func TestCloseDrainsInFlightExport(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := grpc.NewServer(grpc.UnaryInterceptor(func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		close(started)
		<-release
		return handler(ctx, req)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &Collector{server: server, endpoint: listener.Addr().String()}
	collectortrace.RegisterTraceServiceServer(server, collector)
	collectormetrics.RegisterMetricsServiceServer(server, metricsService{collector: collector})
	go func() { _ = server.Serve(listener) }()

	conn, err := grpc.NewClient(collector.Endpoint(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := collectortrace.NewTraceServiceClient(conn)
	exportDone := make(chan error, 1)
	go func() {
		_, err := client.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{})
		exportDone <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("export did not reach the server")
	}

	closeDone := make(chan struct{})
	go func() {
		collector.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		close(release)
		t.Fatal("Close returned before the in-flight export completed")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-exportDone:
		if err != nil {
			t.Fatalf("in-flight export failed during Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight export did not complete")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the export completed")
	}
	collector.Close()
}
