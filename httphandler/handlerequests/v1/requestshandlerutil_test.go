package v1

import (
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/httphandler/config"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsetEnvForTest ensures name is absent from the process environment for the
// duration of the test, restoring whatever value (or absence) it had before.
// Needed because t.Setenv can only set a value, not guarantee absence, and
// defaultScanInfo's KS_SUBMIT handling is presence-sensitive.
func unsetEnvForTest(t *testing.T, name string) {
	t.Helper()
	orig, ok := os.LookupEnv(name)
	require.NoError(t, os.Unsetenv(name))
	t.Cleanup(func() {
		if ok {
			os.Setenv(name, orig)
		} else {
			os.Unsetenv(name)
		}
	})
}

func TestDefaultScanInfo(t *testing.T) {
	// KS_SUBMIT must not leak from the ambient environment (dev machine or CI
	// runner) into this default-value assertion.
	unsetEnvForTest(t, "KS_SUBMIT")

	s := defaultScanInfo()

	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
	assert.Nil(t, s.Submit.Get(), "Submit must not be marked explicitly set by default")
}

func TestDefaultScanInfo_SubmitExplicitlySetFromEnv(t *testing.T) {
	t.Setenv("KS_SUBMIT", "false")

	s := defaultScanInfo()

	assert.False(t, s.Submit.GetBool())
	require.NotNil(t, s.Submit.Get())
}

func TestDefaultScanInfo_KS_SUBMIT_UnparsableValueIgnored(t *testing.T) {
	// Regression test: KS_SUBMIT="" (a common Helm rendering for an unset
	// value) or any other unparsable value must NOT be treated as an
	// explicit opt-out - see https://github.com/kubescape/kubescape/issues/2555.
	for _, v := range []string{"", "yes", "enabled", "no"} {
		t.Run("value="+v, func(t *testing.T) {
			t.Setenv("KS_SUBMIT", v)
			s := defaultScanInfo()
			assert.Nil(t, s.Submit.Get(), "unparsable KS_SUBMIT=%q must not mark Submit as explicitly set", v)
		})
	}
}

func TestDefaultScanInfo_KS_SUBMIT_ParsedValues(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"1", true},
		{"TRUE ", true}, // tolerated: case and surrounding whitespace
		{"false", false},
		{"0", false},
		{" False", false},
	}
	for _, tt := range tests {
		t.Run("value="+tt.raw, func(t *testing.T) {
			t.Setenv("KS_SUBMIT", tt.raw)
			s := defaultScanInfo()
			require.NotNil(t, s.Submit.Get())
			assert.Equal(t, tt.want, s.Submit.GetBool())
		})
	}
}

func TestGetScanCommand(t *testing.T) {
	unsetEnvForTest(t, "KS_SUBMIT")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s, _ := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
}

func TestGetScanCommandWithAccessKey(t *testing.T) {
	unsetEnvForTest(t, "KS_SUBMIT")
	config.SetAccessKey("test-123")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s, _ := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "test-123", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
}

func TestReadResultsFile(t *testing.T) {
	dir := t.TempDir()

	// Temporarily override OutputDir for tests
	oldOutputDir := OutputDir
	OutputDir = dir
	defer func() { OutputDir = oldOutputDir }()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	targetFile := dir + "/" + validUUID + ".json"
	otherFile := dir + "/other-xyz.json"

	err := os.WriteFile(targetFile, []byte("{}"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(otherFile, []byte("{}"), 0644)
	assert.NoError(t, err)

	// readResultsFile should find the target via exact match
	_, err = readResultsFile(validUUID)
	assert.NoError(t, err)

	// readResultsFile should not find a non-existent UUID
	_, err = readResultsFile("111e4567-e89b-12d3-a456-426614174000")
	assert.ErrorContains(t, err, "file 111e4567-e89b-12d3-a456-426614174000 not found")

	// readResultsFile should reject invalid UUID formats
	_, err = readResultsFile("invalid-uuid")
	assert.ErrorContains(t, err, "invalid scan ID format")

	// readResultsFile should prevent path traversal
	_, err = readResultsFile("../target")
	assert.ErrorContains(t, err, "invalid scan ID format")
}

func TestRemoveResultsFile(t *testing.T) {
	dir := t.TempDir()

	// Temporarily override OutputDir for tests
	oldOutputDir := OutputDir
	OutputDir = dir
	defer func() { OutputDir = oldOutputDir }()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	targetFile := dir + "/" + validUUID + ".json"

	err := os.WriteFile(targetFile, []byte("{}"), 0644)
	assert.NoError(t, err)

	// removeResultsFile should succeed
	err = removeResultsFile(validUUID)
	assert.NoError(t, err)
	_, statErr := os.Stat(targetFile)
	assert.True(t, os.IsNotExist(statErr))

	// removeResultsFile should ignore invalid UUID formats
	err = removeResultsFile("invalid-uuid")
	assert.NoError(t, err) // Logs warning, but no error returned

	// removeResultsFile should prevent path traversal
	err = removeResultsFile("../target")
	assert.NoError(t, err)
}
