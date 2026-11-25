package mcpserver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalControlKey(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "nil slice returns empty",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty slice returns empty",
			input:    []string{},
			expected: "",
		},
		{
			name:     "whitespace only elements are omitted",
			input:    []string{"  ", "\t", ""},
			expected: "",
		},
		{
			name:     "single ID is trimmed and uppercased",
			input:    []string{"  c-0012  "},
			expected: "C-0012",
		},
		{
			name:     "multiple IDs are sorted alphabetically",
			input:    []string{"C-0017", "C-0012", "C-0053"},
			expected: url.QueryEscape("C-0012,C-0017,C-0053"),
		},
		{
			name:     "duplicate IDs across cases are deduplicated",
			input:    []string{"C-0012", "c-0012", "C-0017", "C-0017"},
			expected: url.QueryEscape("C-0012,C-0017"),
		},
		{
			name:     "special characters in ID are query escaped and uppercased",
			input:    []string{"C-0012|local", "C-0017"},
			expected: url.QueryEscape("C-0012|LOCAL,C-0017"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalControlKey(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCanonicalFrameworkName(t *testing.T) {
	tests := []struct {
		name        string
		framework   string
		defaultName string
		expected    string
	}{
		{
			name:        "empty framework falls back to lowercased default",
			framework:   "",
			defaultName: "NSA",
			expected:    "nsa",
		},
		{
			name:        "whitespace-only framework falls back to lowercased default",
			framework:   "   \t  ",
			defaultName: "nsa",
			expected:    "nsa",
		},
		{
			name:        "uppercase framework is lowercased",
			framework:   "NSA",
			defaultName: "nsa",
			expected:    "nsa",
		},
		{
			name:        "mixed-case framework with whitespace is trimmed and lowercased",
			framework:   "  Mitre  ",
			defaultName: "nsa",
			expected:    "mitre",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalFrameworkName(tt.framework, tt.defaultName)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestScanCacheKeyDeterminism(t *testing.T) {
	filters := scanFilterArgs{}

	t.Run("scan_manifest cache key without control_ids defaults framework to nsa", func(t *testing.T) {
		manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"
		h := sha256.Sum256([]byte(manifest))

		// Omitted framework
		keyDefault := fmt.Sprintf("scan_manifest:%x:%s:%s%s",
			h[:8], url.QueryEscape(canonicalFrameworkName("", "nsa")), canonicalControlKey(nil), filters.keySuffix())

		// Explicit lower-case nsa
		keyExplicit := fmt.Sprintf("scan_manifest:%x:%s:%s%s",
			h[:8], url.QueryEscape(canonicalFrameworkName("nsa", "nsa")), canonicalControlKey(nil), filters.keySuffix())

		// Uppercase NSA with padding
		keyUpper := fmt.Sprintf("scan_manifest:%x:%s:%s%s",
			h[:8], url.QueryEscape(canonicalFrameworkName("  NSA  ", "nsa")), canonicalControlKey(nil), filters.keySuffix())

		assert.Equal(t, keyDefault, keyExplicit, "omitted framework and explicit 'nsa' must yield identical cache keys")
		assert.Equal(t, keyExplicit, keyUpper, "'nsa' and 'NSA' must yield identical cache keys")
	})

	t.Run("scan_manifest cache key with control_ids ignores framework argument", func(t *testing.T) {
		manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"
		h := sha256.Sum256([]byte(manifest))

		controlIDs1 := []string{"C-0017", "C-0012"}
		controlIDs2 := []string{"c-0012", "C-0017"}

		// When control_ids are present, framework is ignored for key generation
		frameworkEmpty := ""
		frameworkNSA := ""
		if len(controlIDs1) == 0 {
			frameworkEmpty = canonicalFrameworkName("", "nsa")
		}
		if len(controlIDs2) == 0 {
			frameworkNSA = canonicalFrameworkName("nsa", "nsa")
		}

		key1 := fmt.Sprintf("scan_manifest:%x:%s:%s%s",
			h[:8], url.QueryEscape(frameworkEmpty), canonicalControlKey(controlIDs1), filters.keySuffix())
		key2 := fmt.Sprintf("scan_manifest:%x:%s:%s%s",
			h[:8], url.QueryEscape(frameworkNSA), canonicalControlKey(controlIDs2), filters.keySuffix())

		assert.Equal(t, key1, key2, "control_ids scan must have identical key regardless of ordering or framework parameter")
	})

	t.Run("scan_local_iac cache key normalizes framework", func(t *testing.T) {
		path := "deployments/app.yaml"

		keyOmitted := fmt.Sprintf("scan_local_iac:%s:%s%s",
			url.QueryEscape(path), url.QueryEscape(canonicalFrameworkName("", "nsa")), filters.keySuffix())
		keyExplicit := fmt.Sprintf("scan_local_iac:%s:%s%s",
			url.QueryEscape(path), url.QueryEscape(canonicalFrameworkName("nsa", "nsa")), filters.keySuffix())
		keyUpper := fmt.Sprintf("scan_local_iac:%s:%s%s",
			url.QueryEscape(path), url.QueryEscape(canonicalFrameworkName("NSA", "nsa")), filters.keySuffix())

		assert.Equal(t, keyOmitted, keyExplicit)
		assert.Equal(t, keyExplicit, keyUpper)
	})

	t.Run("scan_controls and scan_local_iac_controls sort and deduplicate control_ids", func(t *testing.T) {
		order1 := []string{"C-0017", "C-0012", "C-0012"}
		order2 := []string{"c-0012", "C-0017"}

		keyControls1 := fmt.Sprintf("control_scan:%s:%s%s", "prod", canonicalControlKey(order1), filters.keySuffix())
		keyControls2 := fmt.Sprintf("control_scan:%s:%s%s", "prod", canonicalControlKey(order2), filters.keySuffix())
		assert.Equal(t, keyControls1, keyControls2)

		keyIaC1 := fmt.Sprintf("scan_local_iac_controls:%s:%s%s", url.QueryEscape("main.tf"), canonicalControlKey(order1), filters.keySuffix())
		keyIaC2 := fmt.Sprintf("scan_local_iac_controls:%s:%s%s", url.QueryEscape("main.tf"), canonicalControlKey(order2), filters.keySuffix())
		assert.Equal(t, keyIaC1, keyIaC2)
	})

	t.Run("scanFrameworkKey and scanControlsKey query-escape namespace and normalize star", func(t *testing.T) {
		assert.Equal(t, "framework_scan::nsa", scanFrameworkKey("*", "NSA", ""))
		assert.Equal(t, "framework_scan::nsa", scanFrameworkKey("", "nsa", ""))
		assert.Equal(t, "framework_scan:ns%3Asub:nsa", scanFrameworkKey("ns:sub", "NSA", ""))

		assert.Equal(t, "control_scan::C-0012", scanControlsKey("*", []string{"c-0012"}, ""))
		assert.Equal(t, "control_scan::C-0012", scanControlsKey("", []string{"C-0012"}, ""))
		assert.Equal(t, "control_scan:ns%3Asub:C-0012%2CC-0017", scanControlsKey("ns:sub", []string{"C-0017", "c-0012"}, ""))
	})

	t.Run("toolRemediationKey delegates to canonicalControlKey", func(t *testing.T) {
		key1 := toolRemediationKey("suggest_fix", "app.yaml", "", "", []string{"C-0017", "C-0012"})
		key2 := toolRemediationKey("suggest_fix", "app.yaml", "", "", []string{"c-0012", "C-0017"})
		assert.Equal(t, key1, key2)
	})
}

func TestScanManifest_CallTool_CanonicalCacheHits(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
		s:            server.NewMCPServer("test", "v1"),
	}
	registerTools(ksServer)

	// Call 1: control_ids in order [C-0017, C-0013] with no framework
	res1, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":    samplePrivilegedPodManifest,
		"control_ids": []any{"C-0017", "C-0013"},
	})
	require.NoError(t, err)
	require.False(t, res1.IsError)

	// Call 2: reverse order [c-0013, C-0017] and explicit framework (ignored for cache key when control_ids are present)
	res2, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":    samplePrivilegedPodManifest,
		"control_ids": []any{"c-0013", "C-0017"},
		"framework":   "nsa",
	})
	require.NoError(t, err)
	require.False(t, res2.IsError)

	assert.Equal(t, toolResultText(t, res1), toolResultText(t, res2))
}

func TestScanManifest_CallTool_FrameworkCacheHits(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
		s:            server.NewMCPServer("test", "v1"),
	}
	registerTools(ksServer)

	// Call 1: framework omitted (defaults to nsa)
	res1, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest": samplePrivilegedPodManifest,
	})
	require.NoError(t, err)
	require.False(t, res1.IsError)

	// Call 2: framework explicitly "NSA"
	res2, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":  samplePrivilegedPodManifest,
		"framework": "NSA",
	})
	require.NoError(t, err)
	require.False(t, res2.IsError)

	assert.Equal(t, toolResultText(t, res1), toolResultText(t, res2))
}

func activeScanKeys(ksServer *KubescapeMcpserver) []string {
	ksServer.scanCtxMu.Lock()
	defer ksServer.scanCtxMu.Unlock()
	keys := make([]string, 0, len(ksServer.scanCtxs))
	for k := range ksServer.scanCtxs {
		keys = append(keys, k)
	}
	return keys
}

func TestRunFrameworkSecurityScan_CallTool_EscapedCacheKey(t *testing.T) {
	origFrameworkFn := frameworkScanFn
	t.Cleanup(func() { frameworkScanFn = origFrameworkFn })

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1"),
	}
	registerTools(ksServer)

	var frameworkKeys []string
	frameworkScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace, frameworkName string, filters ...scanFilterArgs) ([]byte, error) {
		frameworkKeys = append(frameworkKeys, activeScanKeys(ksServer)...)
		return []byte(`{"summary":{}}`), nil
	}

	resFw, err := ksServer.CallTool(context.Background(), "run_framework_security_scan", map[string]any{
		"namespace":      "  ns:sub  ",
		"framework_name": "NSA",
	})
	require.NoError(t, err)
	require.False(t, resFw.IsError)
	assert.Equal(t, []string{"framework_scan:ns%3Asub:nsa"}, frameworkKeys)
}

func TestScanControls_CallTool_EscapedCacheKey(t *testing.T) {
	origControlsFn := controlsScanFn
	t.Cleanup(func() { controlsScanFn = origControlsFn })

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1"),
	}
	registerTools(ksServer)

	var controlKeys []string
	controlsScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
		controlKeys = append(controlKeys, activeScanKeys(ksServer)...)
		return []byte(`{"summary":{}}`), nil
	}

	for _, ns := range []any{"*", "   ", "  ns:sub  "} {
		resCtrl, err := ksServer.CallTool(context.Background(), "scan_controls", map[string]any{
			"namespace":   ns,
			"control_ids": []any{"c-0012"},
		})
		require.NoError(t, err)
		require.False(t, resCtrl.IsError)
	}
	assert.Equal(t, []string{
		"control_scan::C-0012",
		"control_scan::C-0012",
		"control_scan:ns%3Asub:C-0012",
	}, controlKeys)
}
