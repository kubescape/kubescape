package mcpserver

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretExposureInspectsBinaryConfigMapContent(t *testing.T) {
	for _, tc := range []struct{ name, value, rule string }{
		{"private key", testPrivateKey(), "PRIVATE_KEY_HEADER"},
		{"github token", testGhToken("binary"), "GITHUB_TOKEN"},
		{"aws key", testAwsKey(), "AWS_ACCESS_KEY_ID"},
		{"connection credentials", testDatabaseURL(), "URI_CREDENTIALS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(tc.value))
			cm := testSecretConfigMapWithBinaryData("prod", "settings", nil, map[string]string{"settings.bin": encoded})
			for _, tool := range []string{"detect_secret_exposure", "analyze_secret_exposure"} {
				server := newSecretExposureTestServer(t, cm)
				result := registeredToolResult(t, dispatchRegisteredTool(t, server, tool, map[string]any{"namespace": "prod", "resource_kind": "ConfigMap"}))
				require.False(t, result.IsError)
				output := toolResultText(t, result)
				var parsed SecretExposureResult
				require.NoError(t, json.Unmarshal([]byte(output), &parsed))
				require.Len(t, parsed.Findings, 1)
				finding := parsed.Findings[0]
				require.Equal(t, tc.rule, finding.RuleID)
				require.Equal(t, "binaryData.settings.bin", finding.Location)
				require.Equal(t, "******", finding.MaskedValue)
				require.NotContains(t, output, tc.value)
				require.NotContains(t, output, encoded)
			}
		})
	}
}

func TestBinaryConfigMapContentControls(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		want             int
	}{
		{name: "ordinary text", key: "settings.bin", value: base64.StdEncoding.EncodeToString([]byte("service listening on port 8080"))},
		{name: "arbitrary binary", key: "settings.bin", value: base64.StdEncoding.EncodeToString([]byte{0, 255, 0, 128, 1})},
		{name: "invalid base64", key: "settings.bin", value: "not-base64!"},
		{name: "sensitive key with opaque bytes", key: "DB_PASSWORD", value: base64.StdEncoding.EncodeToString([]byte{0, 255}), want: 1},
		{name: "sensitive key with invalid base64", key: "DB_PASSWORD", value: "not-base64!", want: 1},
		{name: "encoded placeholder", key: "settings.bin", value: base64.StdEncoding.EncodeToString([]byte("${RUNTIME_TOKEN}"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := testSecretConfigMapWithBinaryData("prod", "settings", nil, map[string]string{tc.key: tc.value})
			findings := scanConfigMap(cm, "prod")
			require.Len(t, findings, tc.want)
			for _, f := range findings {
				require.Equal(t, "******", f.MaskedValue)
			}
		})
	}
}

func TestBinaryConfigMapFindingsStaySeparateFromEnvironment(t *testing.T) {
	token := testGhToken("content")
	cm := testSecretConfigMapWithBinaryData("prod", "settings", nil, map[string]string{"settings.bin": base64.StdEncoding.EncodeToString([]byte(token))})
	pod := testSecretPod("prod", "app", []map[string]any{{"name": "app", "envFrom": []any{map[string]any{"configMapRef": map[string]any{"name": "settings"}}}}})
	server := newSecretExposureTestServer(t, cm, pod)
	result := registeredToolResult(t, dispatchRegisteredTool(t, server, "detect_secret_exposure", map[string]any{"namespace": "prod"}))
	require.False(t, result.IsError)
	var parsed SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Len(t, parsed.Findings, 1)
	require.Equal(t, "ConfigMap", parsed.Findings[0].ResourceKind)
	require.False(t, strings.HasPrefix(parsed.Findings[0].RuleID, "ENVFROM"), "binaryData is not exported by envFrom")
}
