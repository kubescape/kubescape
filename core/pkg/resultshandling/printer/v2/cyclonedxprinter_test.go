package printer

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCycloneDXPrinter(t *testing.T) {
	cp := NewCycloneDXPrinter()
	assert.NotNil(t, cp)
}

func TestSetWriter_CycloneDX(t *testing.T) {
	cp := NewCycloneDXPrinter()
	cp.SetWriter(context.TODO(), "")
	assert.NotNil(t, cp.writer)
	cp.CloseWriter()
}

func TestSetWriter_CycloneDX_AppendsExtension(t *testing.T) {
	cp := NewCycloneDXPrinter()
	tmpDir := t.TempDir()
	cp.SetWriter(context.TODO(), tmpDir+"/report")
	defer cp.CloseWriter()

	assert.Contains(t, cp.writer.Name(), ".cdx.json")
}

func TestSetWriter_CycloneDX_CaseInsensitiveExtension(t *testing.T) {
	cp := NewCycloneDXPrinter()
	tmpDir := t.TempDir()
	cp.SetWriter(context.TODO(), tmpDir+"/Report.CDX.JSON")
	defer cp.CloseWriter()

	assert.NotContains(t, cp.writer.Name(), ".cdx.json.cdx.json")
	assert.Contains(t, cp.writer.Name(), "Report.CDX.JSON")
}

func TestActionPrint_CycloneDX_ImageScan(t *testing.T) {
	imageScanData := []cautils.ImageScanData{buildSeverityExceptionImageScanData()}

	tmp, err := os.CreateTemp("", "cyclonedx-imagescan-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	cp.ActionPrint(context.Background(), nil, imageScanData)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc), "output must be valid JSON")
	assert.Equal(t, "CycloneDX", doc["bomFormat"])
}

func TestActionPrint_CycloneDX_NonImageScan_NoOutput(t *testing.T) {
	tmp, err := os.CreateTemp("", "cyclonedx-noimage-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	cp.ActionPrint(context.Background(), cautils.NewOPASessionObjMock(), nil)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	assert.Empty(t, raw, "cyclonedx-json must not write anything for a non-image scan")
}
