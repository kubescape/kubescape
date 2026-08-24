package telemetry

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Environment variables recognised when --otel-endpoint is not supplied. Names
// and precedence follow the OpenTelemetry protocol exporter specification, so a
// collector already configured for other OTel workloads needs no extra setup.
const (
	EnvEndpoint        = "OTEL_EXPORTER_OTLP_ENDPOINT"
	EnvTracesEndpoint  = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	EnvMetricsEndpoint = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	EnvProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	EnvInsecure        = "OTEL_EXPORTER_OTLP_INSECURE"
	EnvServiceName     = "OTEL_SERVICE_NAME"
)

const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http/protobuf"

	DefaultServiceName = "kubescape"
)

// Config describes how the OTLP exporters should reach a collector. A zero
// Config is disabled and never builds an SDK provider.
type Config struct {
	Endpoint    string
	Protocol    string
	ServiceName string
	Version     string
	Insecure    bool

	// Redact drops resource attributes that identify the machine running the
	// scan. It follows --hide/--encrypt, so a run that anonymizes its report
	// does not describe the host to the collector instead.
	Redact bool

	// FromEnvironment is set when no endpoint was given on the command line.
	// The exporters then read their own OTEL_EXPORTER_OTLP_* variables, which
	// keeps signal-specific endpoints, headers, compression and TLS settings
	// working without this package having to reimplement the whole spec.
	FromEnvironment bool
}

func (c Config) Enabled() bool {
	return c.Endpoint != "" || c.FromEnvironment
}

// ResolveConfig turns the --otel-endpoint value and the process environment
// into an exporter configuration. An empty result means telemetry is off, which
// is the only path that must stay free of SDK setup cost.
func ResolveConfig(flagEndpoint, version string) (Config, error) {
	cfg := Config{
		Protocol:    resolveProtocol(),
		ServiceName: resolveServiceName(),
		Version:     version,
	}
	if cfg.Protocol != ProtocolGRPC && cfg.Protocol != ProtocolHTTP {
		return Config{}, fmt.Errorf("invalid %s %q: supported protocols are %q and %q", EnvProtocol, cfg.Protocol, ProtocolGRPC, ProtocolHTTP)
	}

	flagEndpoint = strings.TrimSpace(flagEndpoint)
	if flagEndpoint == "" {
		cfg.FromEnvironment = hasEndpointInEnvironment()
		return cfg, nil
	}

	endpoint, insecure, err := parseEndpoint(flagEndpoint)
	if err != nil {
		return Config{}, err
	}
	cfg.Endpoint = endpoint
	cfg.Insecure = insecure
	return cfg, nil
}

// parseEndpoint accepts both the "host:port" form used by collector
// documentation and a full URL. A URL's scheme decides transport security;
// a bare authority is treated as plaintext, which is what a local collector on
// 4317 expects and what the --otel-endpoint examples use. Set OTEL_EXPORTER_OTLP_INSECURE=false
// or pass an https:// URL to require TLS.
func parseEndpoint(raw string) (string, bool, error) {
	if !strings.Contains(raw, "://") {
		if strings.ContainsAny(raw, "/?#") {
			return "", false, fmt.Errorf("invalid --otel-endpoint %q: expected host:port or a http(s):// URL", raw)
		}
		if err := validateHostPort(raw); err != nil {
			return "", false, fmt.Errorf("invalid --otel-endpoint %q: %w", raw, err)
		}
		return raw, insecureFromEnv(true), nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("invalid --otel-endpoint %q: %w", raw, err)
	}
	if parsed.Host == "" {
		return "", false, fmt.Errorf("invalid --otel-endpoint %q: missing host", raw)
	}

	switch parsed.Scheme {
	case "http":
		return parsed.Host, insecureFromEnv(true), nil
	case "https":
		return parsed.Host, insecureFromEnv(false), nil
	default:
		return "", false, fmt.Errorf("invalid --otel-endpoint %q: unsupported scheme %q, use http:// or https://", raw, parsed.Scheme)
	}
}

// validateHostPort uses net.SplitHostPort so bracketed IPv6 authorities such as
// [::1]:4317 are accepted rather than tripping over their own colons.
func validateHostPort(raw string) error {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return fmt.Errorf("expected host:port")
	}
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("port %q is not a number", port)
	}
	return nil
}

// insecureFromEnv lets OTEL_EXPORTER_OTLP_INSECURE override the value implied
// by the endpoint, matching how the SDK's own env configuration behaves.
func insecureFromEnv(implied bool) bool {
	value, ok := os.LookupEnv(EnvInsecure)
	if !ok {
		return implied
	}
	insecure, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return implied
	}
	return insecure
}

func hasEndpointInEnvironment() bool {
	for _, name := range []string{EnvEndpoint, EnvTracesEndpoint, EnvMetricsEndpoint} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

func resolveProtocol() string {
	if protocol := strings.TrimSpace(os.Getenv(EnvProtocol)); protocol != "" {
		if protocol == "http" {
			return ProtocolHTTP
		}
		return protocol
	}
	return ProtocolGRPC
}

func resolveServiceName() string {
	if name := strings.TrimSpace(os.Getenv(EnvServiceName)); name != "" {
		return name
	}
	return DefaultServiceName
}
