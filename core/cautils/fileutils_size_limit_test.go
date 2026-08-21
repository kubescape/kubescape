package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFile_EnforcesSizeLimit(t *testing.T) {
	// Use a tiny limit so the test does not need to create a 32 MiB file.
	t.Setenv(MaxFileSizeEnvVar, "1024")
	defer func() { _ = os.Unsetenv(MaxFileSizeEnvVar) }()

	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized.yaml")
	// 2 KiB > 1 KiB limit
	data := make([]byte, 2048)
	for i := range data {
		data[i] = 'A'
	}
	require.NoError(t, os.WriteFile(oversized, data, 0o600))

	_, err := loadFile(oversized)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFileTooLarge)
	assert.Contains(t, err.Error(), "exceeds limit")
}

func TestLoadFile_UnderLimitSucceeds(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "4096")
	dir := t.TempDir()
	small := filepath.Join(dir, "small.yaml")
	content := []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: small\n")
	require.NoError(t, os.WriteFile(small, content, 0o600))

	data, err := loadFile(small)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestLoadFile_ExactlyAtLimitSucceeds(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "10")
	dir := t.TempDir()
	exact := filepath.Join(dir, "exact.yaml")
	require.NoError(t, os.WriteFile(exact, []byte("1234567890"), 0o600)) // 10 bytes

	data, err := loadFile(exact)
	require.NoError(t, err)
	assert.Len(t, data, 10)
}

func TestLoadFile_LimitPlusOneFails(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "10")
	dir := t.TempDir()
	plusOne := filepath.Join(dir, "plusOne.yaml")
	require.NoError(t, os.WriteFile(plusOne, []byte("12345678901"), 0o600)) // 11 bytes

	_, err := loadFile(plusOne)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFileTooLarge)
}

func TestLoadFiles_OversizedIsSkippedNotFatalForDirectory(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "1024")
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	goodContent := []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: good-pod\n  namespace: default\n")
	require.NoError(t, os.WriteFile(good, goodContent, 0o600))

	big := filepath.Join(dir, "big.yaml")
	bigData := make([]byte, 2048)
	for i := range bigData {
		bigData[i] = 'B'
	}
	require.NoError(t, os.WriteFile(big, bigData, 0o600))

	ctx := context.Background()
	workloads, skips, err := LoadResourcesFromFiles(ctx, dir, dir, nil)
	// Directory scan is best-effort: should succeed, keep good workload, report oversized as skip
	require.NoError(t, err, "directory scan with one oversized file must not fail when other workloads exist")
	assert.Len(t, workloads, 1)
	require.Len(t, skips, 1)
	assert.Equal(t, big, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "file too large")
}

func TestLoadFiles_OversizedSingleFileIsHardError(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "1024")
	dir := t.TempDir()
	big := filepath.Join(dir, "big.yaml")
	bigData := make([]byte, 2048)
	for i := range bigData {
		bigData[i] = 'C'
	}
	require.NoError(t, os.WriteFile(big, bigData, 0o600))

	ctx := context.Background()
	workloads, skips, err := LoadResourcesFromFiles(ctx, big, dir, nil)
	require.Error(t, err, "explicit single-file oversized input must be a hard error")
	assert.Empty(t, workloads)
	require.Len(t, skips, 1)
	assert.Contains(t, skips[0].Reason, "file too large")
}

func TestGetMaxFileSize_EnvVarOverride(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "67108864")
	assert.Equal(t, int64(67108864), getMaxFileSize())

	t.Setenv(MaxFileSizeEnvVar, "invalid")
	assert.Equal(t, DefaultMaxFileSize, getMaxFileSize(), "invalid value must fall back to default")

	t.Setenv(MaxFileSizeEnvVar, "-5")
	assert.Equal(t, DefaultMaxFileSize, getMaxFileSize(), "non-positive must fall back to default")

	t.Setenv(MaxFileSizeEnvVar, "9223372036854775807")
	assert.Equal(t, DefaultMaxFileSize, getMaxFileSize(), "math.MaxInt64 must fall back to default to avoid overflow")

	t.Setenv(MaxFileSizeEnvVar, "")
	assert.Equal(t, DefaultMaxFileSize, getMaxFileSize())
}

func TestGetMaxFileSize_MaxInt64IsRejected(t *testing.T) {
	// Regression for overflow: limit+1 with MaxInt64 would wrap to negative and make
	// LimitReader return EOF → empty data instead of ErrFileTooLarge.
	t.Setenv(MaxFileSizeEnvVar, "9223372036854775807")
	assert.Equal(t, DefaultMaxFileSize, getMaxFileSize())

	dir := t.TempDir()
	// File smaller than default 32MiB should still succeed (proves fallback, not MaxInt64)
	small := filepath.Join(dir, "small.yaml")
	require.NoError(t, os.WriteFile(small, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"), 0o600))
	_, err := loadFile(small)
	require.NoError(t, err)
}

func TestLoadFile_DefaultLimitIs32MiB(t *testing.T) {
	// Ensure default is not zero when env is not set
	t.Setenv(MaxFileSizeEnvVar, "")
	// Unset explicitly to test default path
	require.NoError(t, os.Unsetenv(MaxFileSizeEnvVar))
	assert.Equal(t, int64(32<<20), getMaxFileSize())
	assert.Equal(t, int64(32*1024*1024), DefaultMaxFileSize)
}
