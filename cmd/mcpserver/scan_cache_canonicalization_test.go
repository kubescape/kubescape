package mcpserver

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
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
	highFilter := scanFilterArgs{minSeverity: "High"}

	t.Run("scan_manifest cache key without control_ids defaults framework to nsa", func(t *testing.T) {
		manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"
		otherManifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: other\n"

		// Omitted framework
		keyDefault := scanManifestKey(manifest, "", nil, filters.keySuffix())

		// Explicit lower-case nsa
		keyExplicit := scanManifestKey(manifest, "nsa", nil, filters.keySuffix())

		// Uppercase NSA with padding
		keyUpper := scanManifestKey(manifest, "  NSA  ", nil, filters.keySuffix())

		assert.Equal(t, keyDefault, keyExplicit, "omitted framework and explicit 'nsa' must yield identical cache keys")
		assert.Equal(t, keyExplicit, keyUpper, "'nsa' and 'NSA' must yield identical cache keys")
		assert.NotEqual(t, keyDefault, scanManifestKey(otherManifest, "nsa", nil, filters.keySuffix()), "different manifests must yield distinct keys")
		assert.NotEqual(t, keyDefault, scanManifestKey(manifest, "mitre", nil, filters.keySuffix()), "different frameworks must yield distinct keys")
		assert.NotEqual(t, keyDefault, scanManifestKey(manifest, "nsa", nil, highFilter.keySuffix()), "different filter suffixes must yield distinct keys")
	})

	t.Run("scan_manifest cache key with control_ids ignores framework argument", func(t *testing.T) {
		manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"

		controlIDs1 := []string{"C-0017", "C-0012"}
		controlIDs2 := []string{"c-0012", "C-0017"}

		key1 := scanManifestKey(manifest, "", controlIDs1, filters.keySuffix())
		key2 := scanManifestKey(manifest, "nsa", controlIDs2, filters.keySuffix())

		assert.Equal(t, key1, key2, "control_ids scan must have identical key regardless of ordering or framework parameter")
		assert.NotEqual(t, key1, scanManifestKey(manifest, "", []string{"C-0013"}, filters.keySuffix()), "different control_ids must yield distinct keys")
	})

	t.Run("scan_local_iac cache key normalizes framework", func(t *testing.T) {
		path := "deployments/app.yaml"

		keyOmitted := scanLocalIaCKey(path, "", filters.keySuffix())
		keyExplicit := scanLocalIaCKey(path, "nsa", filters.keySuffix())
		keyUpper := scanLocalIaCKey(path, "NSA", filters.keySuffix())

		assert.Equal(t, keyOmitted, keyExplicit)
		assert.Equal(t, keyExplicit, keyUpper)
		assert.NotEqual(t, keyExplicit, scanLocalIaCKey("deployments/other.yaml", "nsa", filters.keySuffix()))
		assert.NotEqual(t, keyExplicit, scanLocalIaCKey(path, "mitre", filters.keySuffix()))
		assert.NotEqual(t, keyExplicit, scanLocalIaCKey(path, "nsa", highFilter.keySuffix()))
	})

	t.Run("scan_controls and scan_local_iac_controls sort and deduplicate control_ids", func(t *testing.T) {
		order1 := []string{"C-0017", "C-0012", "C-0012"}
		order2 := []string{"c-0012", "C-0017"}

		keyControls1 := scanControlsKey("prod", order1, filters.keySuffix())
		keyControls2 := scanControlsKey("prod", order2, filters.keySuffix())
		assert.Equal(t, keyControls1, keyControls2)
		assert.NotEqual(t, keyControls1, scanControlsKey("staging", order1, filters.keySuffix()))
		assert.NotEqual(t, keyControls1, scanControlsKey("prod", []string{"C-0013"}, filters.keySuffix()))
		assert.NotEqual(t, keyControls1, scanControlsKey("prod", order1, highFilter.keySuffix()))

		keyControlsWildcard := scanControlsKey("*", order1, filters.keySuffix())
		keyControlsEmpty := scanControlsKey("", order2, filters.keySuffix())
		assert.Equal(t, keyControlsWildcard, keyControlsEmpty, "'*' and empty namespace must produce identical keys")

		keyIaC1 := scanLocalIaCControlsKey("main.tf", order1, filters.keySuffix())
		keyIaC2 := scanLocalIaCControlsKey("main.tf", order2, filters.keySuffix())
		assert.Equal(t, keyIaC1, keyIaC2)
		assert.NotEqual(t, keyIaC1, scanLocalIaCControlsKey("other.tf", order1, filters.keySuffix()))
		assert.NotEqual(t, keyIaC1, scanLocalIaCControlsKey("main.tf", []string{"C-0013"}, filters.keySuffix()))
		assert.NotEqual(t, keyIaC1, scanLocalIaCControlsKey("main.tf", order1, highFilter.keySuffix()))
	})

	t.Run("scanFrameworkKey and scanControlsKey query-escape namespace and normalize star", func(t *testing.T) {
		assert.Equal(t, "framework_scan::nsa", scanFrameworkKey("*", "NSA", ""))
		assert.Equal(t, "framework_scan::nsa", scanFrameworkKey("", "nsa", ""))
		assert.Equal(t, "framework_scan:ns%3Asub:nsa", scanFrameworkKey("ns:sub", "NSA", ""))

		assert.Equal(t, "control_scan::C-0012", scanControlsKey("*", []string{"c-0012"}, ""))
		assert.Equal(t, "control_scan::C-0012", scanControlsKey("", []string{"C-0012"}, ""))
		assert.Equal(t, "control_scan:ns%3Asub:C-0012%2CC-0017", scanControlsKey("ns:sub", []string{"C-0017", "c-0012"}, ""))
	})

	t.Run("scan_framework normalizes namespace and framework name", func(t *testing.T) {
		key1 := scanFrameworkKey("prod", "NSA", filters.keySuffix())
		key2 := scanFrameworkKey("prod", "nsa", filters.keySuffix())
		assert.Equal(t, key1, key2)
		assert.NotEqual(t, key2, scanFrameworkKey("staging", "nsa", filters.keySuffix()))
		assert.NotEqual(t, key2, scanFrameworkKey("prod", "mitre", filters.keySuffix()))
		assert.NotEqual(t, key2, scanFrameworkKey("prod", "nsa", highFilter.keySuffix()))

		keyWildcard := scanFrameworkKey("*", "nsa", filters.keySuffix())
		keyEmpty := scanFrameworkKey("", "nsa", filters.keySuffix())
		assert.Equal(t, keyWildcard, keyEmpty)
	})

	t.Run("scan_workload normalizes framework name", func(t *testing.T) {
		key1 := scanWorkloadKey("deploy/web", "prod", "", "NSA", filters.keySuffix())
		key2 := scanWorkloadKey("deploy/web", "prod", "", "nsa", filters.keySuffix())
		assert.Equal(t, key1, key2)
		assert.NotEqual(t, key2, scanWorkloadKey("deploy/api", "prod", "", "nsa", filters.keySuffix()))
		assert.NotEqual(t, key2, scanWorkloadKey("deploy/web", "staging", "", "nsa", filters.keySuffix()))
		assert.NotEqual(t, key2, scanWorkloadKey("deploy/web", "prod", "", "mitre", filters.keySuffix()))
		assert.NotEqual(t, key2, scanWorkloadKey("deploy/web", "prod", "", "nsa", highFilter.keySuffix()))
	})

	t.Run("scan_rbac and scan_network keys", func(t *testing.T) {
		assert.Equal(t, "rbac_scan:prod", scanRBACKey("prod", ""))
		assert.NotEqual(t, scanRBACKey("prod", ""), scanRBACKey("staging", ""))
		assert.NotEqual(t, scanRBACKey("prod", ""), scanRBACKey("prod", highFilter.keySuffix()))
		assert.Equal(t, "network_scan:prod", scanNetworkKey("prod", ""))
		assert.NotEqual(t, scanNetworkKey("prod", ""), scanNetworkKey("staging", ""))
		assert.NotEqual(t, scanNetworkKey("prod", ""), scanNetworkKey("prod", highFilter.keySuffix()))
	})

	t.Run("toolRemediationKey delegates to canonicalControlKey", func(t *testing.T) {
		key1 := toolRemediationKey("suggest_fix", "app.yaml", "", "", []string{"C-0017", "C-0012"})
		key2 := toolRemediationKey("suggest_fix", "app.yaml", "", "", []string{"c-0012", "C-0017"})
		assert.Equal(t, key1, key2)
	})
}

func waitForScanCallers(t *testing.T, ksServer *KubescapeMcpserver, flights, callers int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ksServer.scanCtxMu.Lock()
		activeFlights := len(ksServer.scanCtxs)
		totalCallers := 0
		for _, st := range ksServer.scanCtxs {
			totalCallers += st.count
		}
		ksServer.scanCtxMu.Unlock()

		if activeFlights == flights && totalCallers == callers {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d callers across %d flights (have %d callers across %d flights)",
				callers, flights, totalCallers, activeFlights)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertScanReuse(
	t *testing.T,
	toolName string,
	args1 map[string]any,
	args2 map[string]any,
	mockPayload []byte,
	setHook func(scanHook func(ctx context.Context) ([]byte, error)),
) {
	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1"),
	}
	registerTools(ksServer)

	var callCount int32
	var startOnce sync.Once
	scanStarted := make(chan struct{})
	releaseScan := make(chan struct{})

	setHook(func(ctx context.Context) ([]byte, error) {
		atomic.AddInt32(&callCount, 1)
		startOnce.Do(func() { close(scanStarted) })
		select {
		case <-releaseScan:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return mockPayload, nil
	})

	var wg sync.WaitGroup
	var res1, res2 *mcp.CallToolResult
	var err1, err2 error

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseScan)
		})
	}
	t.Cleanup(func() {
		release()
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		res1, err1 = ksServer.CallTool(context.Background(), toolName, args1)
	}()

	// Wait until the first call enters the scan function and is actively in-flight
	select {
	case <-scanStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first scan to start")
	}

	// Wait until caller 1 has registered in scanCtxs (1 flight, 1 caller)
	waitForScanCallers(t, ksServer, 1, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		res2, err2 = ksServer.CallTool(context.Background(), toolName, args2)
	}()

	// Wait until caller 2 joins the in-flight shared execution (1 flight, 2 callers).
	// If the keys did not match, caller 2 would not join flight 1 and this would time out.
	waitForScanCallers(t, ksServer, 1, 2)

	// Release the in-flight scan so both callers complete
	release()
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.False(t, res1.IsError)
	require.False(t, res2.IsError)

	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount), "scan function must be executed exactly once for equivalent canonical inputs")
	assert.Equal(t, toolResultText(t, res1), toolResultText(t, res2))
}

func TestScanManifest_CallTool_CanonicalCacheHits(t *testing.T) {
	orig := manifestScanFn
	t.Cleanup(func() { manifestScanFn = orig })

	manifest := samplePrivilegedPodManifest
	mockRes := []byte(`{"mock":"manifest_scan"}`)

	assertScanReuse(t, "scan_manifest",
		map[string]any{
			"manifest":    manifest,
			"control_ids": []any{"C-0017", "C-0013"},
		},
		map[string]any{
			"manifest":    manifest,
			"control_ids": []any{"c-0013", "C-0017"},
			"framework":   "nsa", // ignored when control_ids are present
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			manifestScanFn = func(s *KubescapeMcpserver, ctx context.Context, manifest, framework string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestScanManifest_CallTool_FrameworkCacheHits(t *testing.T) {
	orig := manifestScanFn
	t.Cleanup(func() { manifestScanFn = orig })

	manifest := samplePrivilegedPodManifest
	mockRes := []byte(`{"mock":"manifest_scan"}`)

	assertScanReuse(t, "scan_manifest",
		map[string]any{
			"manifest": manifest, // omitted framework defaults to nsa
		},
		map[string]any{
			"manifest":  manifest,
			"framework": "  NSA  ", // normalized to nsa
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			manifestScanFn = func(s *KubescapeMcpserver, ctx context.Context, manifest, framework string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestScanLocalIaC_CallTool_FrameworkCacheHits(t *testing.T) {
	orig := localIaCScanFn
	t.Cleanup(func() { localIaCScanFn = orig })

	mockRes := []byte(`{"mock":"local_iac_scan"}`)

	assertScanReuse(t, "scan_local_iac",
		map[string]any{
			"path": "test.yaml",
		},
		map[string]any{
			"path":      "test.yaml",
			"framework": "NSA",
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			localIaCScanFn = func(s *KubescapeMcpserver, ctx context.Context, path, framework string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestScanLocalIaCControls_CallTool_CanonicalCacheHits(t *testing.T) {
	orig := localIaCControlsScanFn
	t.Cleanup(func() { localIaCControlsScanFn = orig })

	mockRes := []byte(`{"mock":"local_iac_controls_scan"}`)

	assertScanReuse(t, "scan_local_iac_controls",
		map[string]any{
			"path":        "test.yaml",
			"control_ids": []any{"C-0017", "C-0013", "C-0017"},
		},
		map[string]any{
			"path":        "test.yaml",
			"control_ids": []any{"c-0013", "C-0017"},
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			localIaCControlsScanFn = func(s *KubescapeMcpserver, ctx context.Context, path string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestScanControls_CallTool_CanonicalCacheHits(t *testing.T) {
	orig := controlsScanFn
	t.Cleanup(func() { controlsScanFn = orig })

	mockRes := []byte(`{"mock":"controls_scan"}`)

	assertScanReuse(t, "scan_controls",
		map[string]any{
			"namespace":   "*",
			"control_ids": []any{"C-0017", "C-0013"},
		},
		map[string]any{
			"namespace":   "",
			"control_ids": []any{"c-0013", "C-0017"},
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			controlsScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestRunFrameworkSecurityScan_CallTool_CanonicalCacheHits(t *testing.T) {
	orig := frameworkScanFn
	t.Cleanup(func() { frameworkScanFn = orig })

	mockRes := []byte(`{"mock":"framework_scan"}`)

	assertScanReuse(t, "run_framework_security_scan",
		map[string]any{
			"namespace":      "*",
			"framework_name": "nsa",
		},
		map[string]any{
			"namespace":      "",
			"framework_name": "NSA",
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			frameworkScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace, frameworkName string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
}

func TestScanWorkload_CallTool_CanonicalCacheHits(t *testing.T) {
	orig := workloadScanFn
	t.Cleanup(func() { workloadScanFn = orig })

	mockRes := []byte(`{"mock":"workload_scan"}`)

	assertScanReuse(t, "scan_workload",
		map[string]any{
			"workload":  "deploy/web",
			"namespace": "default",
			"framework": "nsa",
		},
		map[string]any{
			"workload":  "deploy/web",
			"namespace": "default",
			"framework": "NSA",
		},
		mockRes,
		func(scanHook func(ctx context.Context) ([]byte, error)) {
			workloadScanFn = func(s *KubescapeMcpserver, ctx context.Context, workload, namespace, path, frameworkName string, filters ...scanFilterArgs) ([]byte, error) {
				return scanHook(ctx)
			}
		},
	)
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
