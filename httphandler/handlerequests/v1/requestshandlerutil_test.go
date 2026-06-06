package v1

import (
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/httphandler/config"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func TestDefaultScanInfo(t *testing.T) {
	s := defaultScanInfo()

	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommand(t *testing.T) {
	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommandWithAccessKey(t *testing.T) {
	config.SetAccessKey("test-123")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "test-123", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
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
