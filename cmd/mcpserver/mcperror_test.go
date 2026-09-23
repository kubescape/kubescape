package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestClassifyScanError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorCode
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "invalid workload identifier",
			err:      fmt.Errorf("wrap: %w", cautils.ErrInvalidWorkloadIdentifier),
			expected: ErrCodeMalformedIdentifier,
		},
		{
			name:     "resource not found sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrResourceNotFound),
			expected: ErrCodeResourceNotFound,
		},
		{
			name:     "resource not in discovery sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrResourceNotInDiscovery),
			expected: ErrCodeResourceNotFound,
		},
		{
			name:     "ambiguous resource sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrAmbiguousResource),
			expected: ErrCodeAmbiguousResource,
		},
		{
			name:     "resource has parent sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrResourceHasParent),
			expected: ErrCodeResourceHasParent,
		},
		{
			name:     "not workload sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrNotWorkload),
			expected: ErrCodeNotWorkload,
		},
		{
			name:     "secret scan denied sentinel",
			err:      fmt.Errorf("wrap: %w", resourcehandler.ErrSecretScanDenied),
			expected: ErrCodeSecretScanDenied,
		},
		{
			name:     "apierrors forbidden",
			err:      apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "nginx", errors.New("forbidden")),
			expected: ErrCodeRBACDenied,
		},
		{
			name:     "apierrors not found",
			err:      apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "nginx"),
			expected: ErrCodeResourceNotFound,
		},
		{
			name:     "apierrors unauthorized maps to k8s client error",
			err:      apierrors.NewUnauthorized("unauthorized"),
			expected: ErrCodeK8sClientError,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: ErrCodeTimeout,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: ErrCodeTimeout,
		},
		{
			name:     "generic unknown error",
			err:      errors.New("something totally unknown"),
			expected: ErrCodeScanFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := classifyScanError(tt.err)
			assert.Equal(t, tt.expected, code)
		})
	}
}

func TestClassifyScanError_IntegrationWithResourceHandler(t *testing.T) {
	sentinelMappings := []struct {
		sentinel error
		expected ErrorCode
	}{
		{resourcehandler.ErrResourceNotFound, ErrCodeResourceNotFound},
		{resourcehandler.ErrResourceNotInDiscovery, ErrCodeResourceNotFound},
		{resourcehandler.ErrAmbiguousResource, ErrCodeAmbiguousResource},
		{resourcehandler.ErrResourceHasParent, ErrCodeResourceHasParent},
		{resourcehandler.ErrNotWorkload, ErrCodeNotWorkload},
		{resourcehandler.ErrSecretScanDenied, ErrCodeSecretScanDenied},
	}

	for _, sm := range sentinelMappings {
		t.Run(string(sm.expected), func(t *testing.T) {
			wrapped := fmt.Errorf("failed to pull resource: %w", sm.sentinel)
			code := classifyScanError(wrapped)
			assert.Equal(t, sm.expected, code)
		})
	}
}

func TestClassifyScanErrorMessage(t *testing.T) {
	err := errors.New("detailed root cause")
	tests := []struct {
		code     ErrorCode
		label    string
		contains []string
	}{
		{ErrCodeMalformedIdentifier, "workload", []string{"invalid workload identifier", "detailed root cause"}},
		{ErrCodeResourceNotFound, "workload", []string{"resource not found", "detailed root cause"}},
		{ErrCodeAmbiguousResource, "workload", []string{"ambiguous resource match", "detailed root cause"}},
		{ErrCodeResourceHasParent, "workload", []string{"parent controller", "detailed root cause"}},
		{ErrCodeNotWorkload, "workload", []string{"not a scannable workload", "detailed root cause"}},
		{ErrCodeSecretScanDenied, "workload", []string{"Secret resources is not supported", "detailed root cause"}},
		{ErrCodeRBACDenied, "workload", []string{"insufficient permissions", "detailed root cause"}},
		{ErrCodeK8sClientError, "workload", []string{"kubernetes client error during workload scan", "detailed root cause"}},
		{ErrCodeTimeout, "workload", []string{"workload scan timed out", "detailed root cause"}},
		{ErrCodeScanFailed, "workload", []string{"failed to run workload scan", "detailed root cause"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			msg := classifyScanErrorMessage(tt.code, tt.label, err)
			for _, substr := range tt.contains {
				assert.Contains(t, msg, substr)
			}
		})
	}
}

func TestMcpToolError(t *testing.T) {
	result := mcpToolError(ErrCodeInvalidArgument, "invalid input", map[string]any{
		"argument": "path",
	})
	require.NotNil(t, result)
	assert.True(t, result.IsError)
	require.Len(t, result.Content, 1)

	var payload ToolError
	text := result.Content[0].(mcp.TextContent).Text
	err := json.Unmarshal([]byte(text), &payload)
	require.NoError(t, err)

	assert.Equal(t, ErrCodeInvalidArgument, payload.Code)
	assert.Equal(t, "invalid input", payload.Message)
	assert.Equal(t, "path", payload.Details["argument"])
}

func TestSanitizeDetails(t *testing.T) {
	assert.Nil(t, sanitizeDetails(nil))

	input := map[string]any{
		"str":       "valid",
		"integer":   42,
		"int64":     int64(100),
		"float":     3.14,
		"boolean":   true,
		"str_slice": []string{"a", "b"},
		// The following unsafe types should be dropped:
		"byte_slice": []byte("secrets"),
		"map":        map[string]string{"foo": "bar"},
		"struct":     struct{ X string }{X: "leak"},
	}

	sanitized := sanitizeDetails(input)
	assert.Equal(t, "valid", sanitized["str"])
	assert.Equal(t, 42, sanitized["integer"])
	assert.Equal(t, int64(100), sanitized["int64"])
	assert.Equal(t, 3.14, sanitized["float"])
	assert.Equal(t, true, sanitized["boolean"])
	assert.Equal(t, []string{"a", "b"}, sanitized["str_slice"])

	assert.NotContains(t, sanitized, "byte_slice")
	assert.NotContains(t, sanitized, "map")
	assert.NotContains(t, sanitized, "struct")
}

func TestMcpRequiredStringArg(t *testing.T) {
	tests := []struct {
		name      string
		arguments map[string]any
		param     string
		wantVal   string
		wantErr   bool
	}{
		{
			name:      "valid string",
			arguments: map[string]any{"target": "  nginx  "},
			param:     "target",
			wantVal:   "nginx",
			wantErr:   false,
		},
		{
			name:      "missing parameter",
			arguments: map[string]any{},
			param:     "target",
			wantVal:   "",
			wantErr:   true,
		},
		{
			name:      "null parameter",
			arguments: map[string]any{"target": nil},
			param:     "target",
			wantVal:   "",
			wantErr:   true,
		},
		{
			name:      "empty string",
			arguments: map[string]any{"target": "   "},
			param:     "target",
			wantVal:   "",
			wantErr:   true,
		},
		{
			name:      "non-string value",
			arguments: map[string]any{"target": 12345},
			param:     "target",
			wantVal:   "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, toolErr := mcpRequiredStringArg(tt.arguments, tt.param)
			if tt.wantErr {
				assert.NotNil(t, toolErr)
				assert.True(t, toolErr.IsError)
				assert.Empty(t, val)
			} else {
				assert.Nil(t, toolErr)
				assert.Equal(t, tt.wantVal, val)
			}
		})
	}
}

func TestErrorCodes_AllReferenced(t *testing.T) {
	allCodes := []string{
		"ErrCodeMalformedIdentifier",
		"ErrCodeResourceNotFound",
		"ErrCodeAmbiguousResource",
		"ErrCodeRBACDenied",
		"ErrCodeInvalidArgument",
		"ErrCodeScanFailed",
		"ErrCodeK8sClientError",
		"ErrCodeMarshalError",
		"ErrCodeTimeout",
		"ErrCodeResourceHasParent",
		"ErrCodeNotWorkload",
		"ErrCodeSecretScanDenied",
		"ErrCodeUnsupportedResource",
	}

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	var combinedSource strings.Builder
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "mcperror.go" {
			continue
		}
		content, err := os.ReadFile(file)
		require.NoError(t, err)
		combinedSource.Write(content)
		combinedSource.WriteString("\n")
	}

	sourceText := combinedSource.String()
	for _, code := range allCodes {
		assert.True(t, strings.Contains(sourceText, code),
			"ErrorCode constant %s must be referenced in at least one non-test source file outside mcperror.go", code)
	}
}
