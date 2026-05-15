package core

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

// redirectHome redirects HOME to a temp dir for the duration of the test.
// This prevents SetCachedConfig / DeleteCachedConfig from touching the
// real ~/.kubescape on the developer's or CI machine.
func redirectHome(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	t.Cleanup(func() {
		os.Setenv("HOME", origHome)
	})
}

func TestSetCachedConfig_AllFields(t *testing.T) {
	redirectHome(t)

	ks := &Kubescape{}
	setConfig := &metav1.SetConfig{
		Account:        "test-account",
		AccessKey:      "test-access-key",
		CloudAPIURL:    "https://api.test.com",
		CloudReportURL: "https://report.test.com",
	}

	err := ks.SetCachedConfig(setConfig)
	assert.NoError(t, err)

	// Read back and assert all fields were persisted
	var buf bytes.Buffer
	err = ks.ViewCachedConfig(&metav1.ViewConfig{Writer: &buf})
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "test-account")
	assert.Contains(t, output, "test-access-key")
	assert.Contains(t, output, "https://api.test.com")
	assert.Contains(t, output, "https://report.test.com")
}

func TestSetCachedConfig_EmptyFields(t *testing.T) {
	redirectHome(t)

	ks := &Kubescape{}

	// Step 1: seed with real values first
	err := ks.SetCachedConfig(&metav1.SetConfig{
		Account:        "seed-account",
		AccessKey:      "seed-key",
		CloudAPIURL:    "https://seed-api",
		CloudReportURL: "https://seed-report",
	})
	assert.NoError(t, err)

	// Step 2: apply empty fields — should NOT overwrite existing values
	err = ks.SetCachedConfig(&metav1.SetConfig{
		Account:        "",
		AccessKey:      "",
		CloudAPIURL:    "",
		CloudReportURL: "",
	})
	assert.NoError(t, err)

	// Step 3: verify original seeded values are still intact
	var buf bytes.Buffer
	err = ks.ViewCachedConfig(&metav1.ViewConfig{Writer: &buf})
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "seed-account")
	assert.Contains(t, output, "seed-key")
	assert.Contains(t, output, "https://seed-api")
	assert.Contains(t, output, "https://seed-report")
}

func TestDeleteCachedConfig(t *testing.T) {
	redirectHome(t)

	ks := &Kubescape{}

	// Step 1: seed a config so there is something to delete
	err := ks.SetCachedConfig(&metav1.SetConfig{
		Account:        "to-delete-account",
		AccessKey:      "to-delete-key",
		CloudAPIURL:    "https://delete-api",
		CloudReportURL: "https://delete-report",
	})
	assert.NoError(t, err)

	// Step 2: delete the cached config
	err = ks.DeleteCachedConfig(&metav1.DeleteConfig{})
	assert.NoError(t, err)

	// Step 3: verify the seeded values are no longer present
	var buf bytes.Buffer
	err = ks.ViewCachedConfig(&metav1.ViewConfig{Writer: &buf})
	assert.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "to-delete-account")
	assert.NotContains(t, output, "to-delete-key")
}
