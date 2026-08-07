package getter

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSecurityExceptionToPosturePolicy_AlertOnly(t *testing.T) {
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "NSA", "alert_only", "", "known issue", nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "C-0034", policy.PosturePolicies[0].ControlID)
	assert.Equal(t, "NSA", policy.PosturePolicies[0].FrameworkName)
	assert.True(t, policy.IsAlertOnly())
	assert.Equal(t, "my-exception/C-0034", policy.Name)
	require.NotNil(t, policy.Reason)
	assert.Equal(t, "known issue", *policy.Reason)
}

func TestConvertSecurityExceptionToPosturePolicy_Ignore(t *testing.T) {
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0017", "", "ignore", "", "", nil,
	)
	require.NoError(t, err)
	assert.True(t, policy.IsDisable())
}

func TestConvertSecurityExceptionToPosturePolicy_EmptyActionDefaultsToAlertOnly(t *testing.T) {
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "", "", "", nil,
	)
	require.NoError(t, err)
	assert.True(t, policy.IsAlertOnly())
}

func TestConvertSecurityExceptionToPosturePolicy_UnknownActionErrors(t *testing.T) {
	_, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "invalid-action", "", "", nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown action")
}

func TestConvertSecurityExceptionToPosturePolicy_ExpiresAt(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "alert_only", future, "", nil,
	)
	require.NoError(t, err)
	require.NotNil(t, policy.ExpirationDate)
	assert.True(t, policy.ExpirationDate.After(time.Now()))
}

func TestConvertSecurityExceptionToPosturePolicy_InvalidExpiresAt(t *testing.T) {
	_, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "alert_only", "not-a-date", "", nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expiresAt")
}

func TestConvertSecurityExceptionToPosturePolicy_ResourceDesignators(t *testing.T) {
	resources := []map[string]string{
		{"kind": "Deployment", "name": "nginx"},
	}
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "alert_only", "", "", resources,
	)
	require.NoError(t, err)
	require.Len(t, policy.Resources, 1)
	assert.Equal(t, "Deployment", policy.Resources[0].Attributes["kind"])
	assert.Equal(t, "nginx", policy.Resources[0].Attributes["name"])
}

func TestConvertSecurityExceptionToPosturePolicy_PolicyType(t *testing.T) {
	policy, err := convertSecurityExceptionToPosturePolicy(
		"my-exception", "C-0034", "", "alert_only", "", "", nil,
	)
	require.NoError(t, err)
	assert.Equal(t, string(armotypes.PostureExceptionPolicyType), policy.PolicyType)
}
