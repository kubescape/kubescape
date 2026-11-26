package v1alpha1

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePercentage(t *testing.T) {
	floatPtr := func(v float64) *float64 { return &v }

	tests := []struct {
		name    string
		value   *float64
		wantErr bool
	}{
		{name: "nil pointer is valid", value: nil},
		{name: "lower boundary 0", value: floatPtr(0)},
		{name: "mid-range percentage", value: floatPtr(75.5)},
		{name: "upper boundary 100", value: floatPtr(100)},
		{name: "negative value rejected", value: floatPtr(-0.1), wantErr: true},
		{name: "above 100 rejected", value: floatPtr(100.1), wantErr: true},
		{name: "NaN rejected", value: floatPtr(math.NaN()), wantErr: true},
		{name: "positive Inf rejected", value: floatPtr(math.Inf(1)), wantErr: true},
		{name: "negative Inf rejected", value: floatPtr(math.Inf(-1)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePercentage("spec.contracts.ci.failure.complianceBelow", tt.value)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "must be between 0 and 100")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateStringList(t *testing.T) {
	tests := []struct {
		name        string
		values      *StringList
		errContains string
	}{
		{name: "nil list is valid", values: nil},
		{name: "empty list is valid", values: &StringList{}},
		{name: "distinct non-empty items", values: &StringList{"nsa", "mitre", "cis-v1.23-t1.0.1"}},
		{name: "whitespace-only item rejected", values: &StringList{"nsa", "   "}, errContains: "contains an empty value"},
		{name: "case-insensitive duplicate rejected", values: &StringList{"NSA", " nsa "}, errContains: "contains duplicate value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStringList("spec.contracts.ci.policy.frameworks", tt.values)
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestContainsFold(t *testing.T) {
	values := []string{"json", "SARIF", "junit"}

	assert.True(t, containsFold(values, "json"))
	assert.True(t, containsFold(values, "sarif"))
	assert.True(t, containsFold(values, "JUNIT"))
	assert.False(t, containsFold(values, "pdf"))
	assert.False(t, containsFold(nil, "json"))
}

func TestValidateVersionEnvelope(t *testing.T) {
	tests := []struct {
		name           string
		apiVersion     string
		kind           string
		minimumVersion string
		runningVersion string
		errContains    string
	}{
		{
			name:           "valid matching release version",
			apiVersion:     APIVersion,
			kind:           Kind,
			minimumVersion: "v4.0.0",
			runningVersion: "v4.0.0",
		},
		{
			name:           "newer running release version",
			apiVersion:     APIVersion,
			kind:           Kind,
			minimumVersion: "v4.0.0",
			runningVersion: "v4.2.1",
		},
		{
			name:           "non-semver development build skips compatibility check",
			apiVersion:     APIVersion,
			kind:           Kind,
			minimumVersion: "v4.0.0",
			runningVersion: "dev",
		},
		{
			name:           "unsupported apiVersion",
			apiVersion:     "config.kubescape.io/v99",
			kind:           Kind,
			minimumVersion: "v4.0.0",
			runningVersion: "v4.0.0",
			errContains:    "unsupported apiVersion",
		},
		{
			name:           "unsupported kind",
			apiVersion:     APIVersion,
			kind:           "OtherKind",
			minimumVersion: "v4.0.0",
			runningVersion: "v4.0.0",
			errContains:    "unsupported kind",
		},
		{
			name:           "invalid minimum semver",
			apiVersion:     APIVersion,
			kind:           Kind,
			minimumVersion: "4.0.0",
			runningVersion: "v4.0.0",
			errContains:    "not a valid semantic version",
		},
		{
			name:           "running version older than minimum",
			apiVersion:     APIVersion,
			kind:           Kind,
			minimumVersion: "v4.1.0",
			runningVersion: "v4.0.9",
			errContains:    "requires Kubescape v4.1.0 or newer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVersionEnvelope(tt.apiVersion, tt.kind, tt.minimumVersion, tt.runningVersion)
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}
