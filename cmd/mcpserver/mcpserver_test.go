package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
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
	ksServer := &KubescapeMcpserver{}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcp.ReadResourceRequest{}
			req.Params.URI = tt.uri

			if tt.passParse {
				defer func() {
					r := recover()
					if r == nil {
						t.Fatal("expected panic from nil ksClient after successful URI parse, got none")
					}
				}()
				_, _ = ksServer.ReadConfigurationResource(context.Background(), req)
				t.Fatal("expected panic, but call returned normally")
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
