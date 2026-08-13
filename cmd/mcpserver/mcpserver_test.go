package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/mcp"

	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
)

func TestParseVulnManifestURI(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		wantErr      string // substring expected in error; empty = expect success
		wantNS       string
		wantManifest string
		wantCVE      string
	}{
		{
			name:    "wrong scheme",
			uri:     "other://vulnerability-manifests/ns/manifest/cve_list",
			wantErr: "invalid URI",
		},
		{
			name:         "base URI defaults to cve_list",
			uri:          "kubescape://vulnerability-manifests/ns/manifest",
			wantNS:       "ns",
			wantManifest: "manifest",
		},
		{
			name:         "valid cve_list URI",
			uri:          "kubescape://vulnerability-manifests/default/my-manifest/cve_list",
			wantNS:       "default",
			wantManifest: "my-manifest",
		},
		{
			name:         "valid cve_details URI",
			uri:          "kubescape://vulnerability-manifests/default/my-manifest/cve_details/CVE-2024-1234",
			wantNS:       "default",
			wantManifest: "my-manifest",
			wantCVE:      "CVE-2024-1234",
		},
		{
			name:    "only namespace (too few parts)",
			uri:     "kubescape://vulnerability-manifests/ns",
			wantErr: "invalid URI",
		},
		{
			name:    "too many parts",
			uri:     "kubescape://vulnerability-manifests/ns/manifest/cve_details/CVE-1/extra",
			wantErr: "invalid URI",
		},
		{
			name:    "wrong action with 3 parts",
			uri:     "kubescape://vulnerability-manifests/ns/manifest/not_cve_list",
			wantErr: "invalid URI",
		},
		{
			name:    "wrong action with 4 parts",
			uri:     "kubescape://vulnerability-manifests/ns/manifest/not_cve_details/CVE-1",
			wantErr: "invalid URI",
		},
		{
			name:    "empty namespace",
			uri:     "kubescape://vulnerability-manifests//manifest/cve_list",
			wantErr: "invalid URI",
		},
		{
			name:    "empty manifest name",
			uri:     "kubescape://vulnerability-manifests/ns//cve_list",
			wantErr: "invalid URI",
		},
		{
			name:    "empty CVE ID",
			uri:     "kubescape://vulnerability-manifests/ns/manifest/cve_details/",
			wantErr: "invalid URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseVulnManifestURI(tt.uri)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.namespace != tt.wantNS {
				t.Errorf("namespace = %q, want %q", parsed.namespace, tt.wantNS)
			}
			if parsed.manifestName != tt.wantManifest {
				t.Errorf("manifestName = %q, want %q", parsed.manifestName, tt.wantManifest)
			}
			if parsed.cveID != tt.wantCVE {
				t.Errorf("cveID = %q, want %q", parsed.cveID, tt.wantCVE)
			}
		})
	}
}

func TestReadConfigurationResource_URIParsing(t *testing.T) {
	expectedErr := fmt.Errorf("sentinel connection error")
	ksServer := &KubescapeMcpserver{
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			return nil, expectedErr
		},
	}

	tests := []struct {
		name      string
		uri       string
		wantErr   string
		passParse bool
	}{
		{
			name:    "wrong scheme",
			uri:     "other://configuration-manifests/ns/manifest",
			wantErr: "invalid URI",
		},
		{
			name:      "valid URI",
			uri:       "kubescape://configuration-manifests/default/my-config",
			passParse: true,
		},
		{
			name:    "too few parts",
			uri:     "kubescape://configuration-manifests/ns",
			wantErr: "invalid URI",
		},
		{
			name:    "too many parts",
			uri:     "kubescape://configuration-manifests/ns/manifest/extra",
			wantErr: "invalid URI",
		},
		{
			name:    "empty namespace",
			uri:     "kubescape://configuration-manifests//manifest",
			wantErr: "invalid URI",
		},
		{
			name:    "empty manifest name",
			uri:     "kubescape://configuration-manifests/ns/",
			wantErr: "invalid URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.ReadResourceRequest{}
			req.Params.URI = tt.uri

			if tt.passParse {
				_, err := ksServer.ReadConfigurationResource(context.Background(), req)
				if err == nil {
					t.Fatal("expected error from ksClient, got nil")
				}
				if !strings.Contains(err.Error(), "sentinel connection error") {
					t.Errorf("expected error containing 'sentinel connection error', got %v", err)
				}
			} else {
				_, err := ksServer.ReadConfigurationResource(context.Background(), req)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestReadContainerProfileResource_URIParsing(t *testing.T) {
	expectedErr := fmt.Errorf("sentinel connection error")
	ksServer := &KubescapeMcpserver{
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			return nil, expectedErr
		},
	}

	tests := []struct {
		name      string
		uri       string
		wantErr   string
		passParse bool
	}{
		{
			name:    "wrong scheme",
			uri:     "other://container-profiles/ns/manifest",
			wantErr: "invalid URI",
		},
		{
			name:      "valid URI",
			uri:       "kubescape://container-profiles/default/my-profile",
			passParse: true,
		},
		{
			name:    "too few parts",
			uri:     "kubescape://container-profiles/ns",
			wantErr: "invalid URI",
		},
		{
			name:    "too many parts",
			uri:     "kubescape://container-profiles/ns/manifest/extra",
			wantErr: "invalid URI",
		},
		{
			name:    "empty namespace",
			uri:     "kubescape://container-profiles//profile",
			wantErr: "invalid URI",
		},
		{
			name:    "empty profile name",
			uri:     "kubescape://container-profiles/ns/",
			wantErr: "invalid URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.ReadResourceRequest{}
			req.Params.URI = tt.uri

			if tt.passParse {
				_, err := ksServer.ReadContainerProfileResource(context.Background(), req)
				if err == nil {
					t.Fatal("expected error from ksClient, got nil")
				}
				if !strings.Contains(err.Error(), "sentinel connection error") {
					t.Errorf("expected error containing 'sentinel connection error', got %v", err)
				}
			} else {
				_, err := ksServer.ReadContainerProfileResource(context.Background(), req)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestCallTool_RunFrameworkScan(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	tests := []struct {
		name          string
		arguments     map[string]any
		wantErrString string
	}{
		{
			name:          "missing framework_name",
			arguments:     map[string]any{},
			wantErrString: "framework_name argument is required",
		},
		{
			name: "framework_name not a string",
			arguments: map[string]any{
				"framework_name": 123,
			},
			wantErrString: "framework_name argument must be a string",
		},
		{
			name: "empty framework_name",
			arguments: map[string]any{
				"framework_name": "",
			},
			wantErrString: "framework_name argument must not be empty",
		},
		{
			name: "whitespace framework_name",
			arguments: map[string]any{
				"framework_name": "   ",
			},
			wantErrString: "framework_name argument must not be empty",
		},
		{
			name: "allcontrols framework_name rejected (case-insensitive)",
			arguments: map[string]any{
				"framework_name": "AllControls",
			},
			wantErrString: "is exceptionally heavy and is not supported in the headless MCP scanner",
		},
		{
			name: "namespace not a string",
			arguments: map[string]any{
				"framework_name": "nsa",
				"namespace":      123,
			},
			wantErrString: "namespace argument must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ksServer.CallTool(context.Background(), "run_framework_security_scan", tt.arguments)
			if err != nil {
				t.Fatalf("unexpected error from CallTool itself: %v", err)
			}
			if res.IsError == false {
				t.Fatalf("expected error result, got success")
			}
			if !strings.Contains(res.Content[0].(mcp.TextContent).Text, tt.wantErrString) {
				t.Errorf("expected error containing %q, got %q", tt.wantErrString, res.Content[0].(mcp.TextContent).Text)
			}
		})
	}
}

func TestGetKsClient_RetriesAfterTransientFailure(t *testing.T) {
	sentinelErr := fmt.Errorf("transient init failure")
	calls := 0
	fakeClient := struct {
		spdxv1beta1.SpdxV1beta1Interface
	}{}
	ksServer := &KubescapeMcpserver{
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			calls++
			if calls == 1 {
				return nil, sentinelErr
			}
			return fakeClient, nil
		},
	}

	_, err := ksServer.getKsClient()
	if err == nil || !strings.Contains(err.Error(), "transient init failure") {
		t.Fatalf("expected transient init failure on first call, got: %v", err)
	}

	client, err := ksServer.getKsClient()
	if err != nil {
		t.Fatalf("expected retry to succeed after transient failure, got error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client after successful retry")
	}
	if calls != 2 {
		t.Fatalf("expected init to be called twice (once failing, once succeeding), got %d calls", calls)
	}

	// A subsequent call must reuse the cached successful client, not re-init.
	if _, err := ksServer.getKsClient(); err != nil {
		t.Fatalf("unexpected error on cached client call: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected init not to be called again once a client is cached, got %d calls", calls)
	}
}

func TestGetKsClient_DefaultInitializerIsUsedAndCached(t *testing.T) {
	origNewKsClient := newKsClient
	t.Cleanup(func() { newKsClient = origNewKsClient })

	calls := 0
	fakeClient := struct {
		spdxv1beta1.SpdxV1beta1Interface
	}{}
	newKsClient = func() (spdxv1beta1.SpdxV1beta1Interface, error) {
		calls++
		return fakeClient, nil
	}

	ksServer := &KubescapeMcpserver{}
	first, err := ksServer.getKsClient()
	if err != nil {
		t.Fatalf("unexpected error from default initializer: %v", err)
	}
	second, err := ksServer.getKsClient()
	if err != nil {
		t.Fatalf("unexpected error from cached default initializer: %v", err)
	}
	if first != fakeClient || second != fakeClient {
		t.Fatal("expected the default initializer client to be cached and reused")
	}
	if calls != 1 {
		t.Fatalf("expected default initializer to run once, got %d calls", calls)
	}
}

func TestGetK8sClient_NotConnectedReturnsError(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	origNewK8sClient := newK8sClient
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
		newK8sClient = origNewK8sClient
	})

	loadK8sConfig = func() error { return errors.New("no kubeconfig") }
	setConnectedToCluster = func(bool) {}
	calledConstructor := false
	newK8sClient = func() *k8sinterface.KubernetesApi {
		calledConstructor = true
		return &k8sinterface.KubernetesApi{}
	}

	ksServer := &KubescapeMcpserver{}
	client, err := ksServer.getK8sClient()
	if err == nil {
		t.Fatal("expected error when no cluster is reachable, got nil")
	}
	if client != nil {
		t.Fatalf("expected nil client on error, got %v", client)
	}
	if calledConstructor {
		t.Fatal("expected constructor not to run when cluster connectivity is absent")
	}
}

func TestGetK8sClient_InitializesOnceAndCachesClient(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	origNewK8sClient := newK8sClient
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
		newK8sClient = origNewK8sClient
	})

	loadK8sConfig = func() error { return nil }
	setConnectedToCluster = func(bool) {}
	calls := 0
	fakeClient := &k8sinterface.KubernetesApi{}
	newK8sClient = func() *k8sinterface.KubernetesApi {
		calls++
		return fakeClient
	}

	ksServer := &KubescapeMcpserver{}
	first, err := ksServer.getK8sClient()
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	second, err := ksServer.getK8sClient()
	if err != nil {
		t.Fatalf("unexpected error reusing cached client: %v", err)
	}
	if first != fakeClient || second != fakeClient {
		t.Fatal("expected constructed client to be cached and reused")
	}
	if calls != 1 {
		t.Fatalf("expected constructor to run once, got %d calls", calls)
	}
}

// TestGetK8sClient_RetriesAfterTransientLoadFailure guards against
// k8sinterface.IsConnectedToCluster's one-way latch: it only ever moves to
// false, so a naive connectivity check would return the same error forever
// after one transient kubeconfig read failure. getK8sClient must retry via
// loadK8sConfig instead, which has no such latch.
func TestGetK8sClient_RetriesAfterTransientLoadFailure(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	origNewK8sClient := newK8sClient
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
		newK8sClient = origNewK8sClient
	})

	loadErr := errors.New("transient kubeconfig read failure")
	shouldFail := true
	loadK8sConfig = func() error {
		if shouldFail {
			return loadErr
		}
		return nil
	}
	var latch bool
	setConnectedToCluster = func(connected bool) { latch = connected }
	fakeClient := &k8sinterface.KubernetesApi{}
	newK8sClient = func() *k8sinterface.KubernetesApi { return fakeClient }

	ksServer := &KubescapeMcpserver{}

	if _, err := ksServer.getK8sClient(); err == nil {
		t.Fatal("expected error on first, transient failure")
	}
	if latch {
		t.Fatal("expected the connectivity latch to be false after a failed load")
	}

	shouldFail = false
	client, err := ksServer.getK8sClient()
	if err != nil {
		t.Fatalf("expected retry to succeed after the transient condition cleared, got: %v", err)
	}
	if client != fakeClient {
		t.Fatalf("expected retried call to return the constructed client, got %v", client)
	}
	if !latch {
		t.Fatal("expected the connectivity latch to be cleared to true on successful retry")
	}
}
