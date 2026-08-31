package printer

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
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

func TestActionPrint_CycloneDX_PostureScanWithoutImages_NoOutput(t *testing.T) {
	tmp, err := os.CreateTemp("", "cyclonedx-noimage-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	err = cp.ActionPrint(context.Background(), cautils.NewOPASessionObjMock(), nil)
	require.Error(t, err)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	assert.Empty(t, raw, "cyclonedx-json must not write anything when no image was scanned")
}

func TestActionPrint_CycloneDX_MultiImageScan(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		buildSeverityExceptionImageScanData(),
		buildSeverityExceptionImageScanData(),
	}

	tmp, err := os.CreateTemp("", "cyclonedx-multi-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	err = cp.ActionPrint(context.Background(), nil, imageScanData)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	var docs []map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &docs), "multi-image CycloneDX output must be valid JSON array")
	assert.Len(t, docs, 2)
	assert.Equal(t, "CycloneDX", docs[0]["bomFormat"])
	assert.Equal(t, "CycloneDX", docs[1]["bomFormat"])
}

func TestActionPrint_CycloneDX_PartialNilSBOM(t *testing.T) {
	validScan := buildSeverityExceptionImageScanData()
	nilScan := cautils.ImageScanData{SBOM: nil}

	imageScanData := []cautils.ImageScanData{nilScan, validScan}

	tmp, err := os.CreateTemp("", "cyclonedx-partial-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	err = cp.ActionPrint(context.Background(), nil, imageScanData)
	require.NoError(t, err, "must succeed by processing the valid SBOM while skipping the nil SBOM")
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc), "single valid SBOM in partial scan must be valid JSON document")
	assert.Equal(t, "CycloneDX", doc["bomFormat"])
}

func TestActionPrint_CycloneDX_AllNilSBOMs_ReturnsError(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		{SBOM: nil},
		{SBOM: nil},
	}

	tmp, err := os.CreateTemp("", "cyclonedx-allnil-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	err = cp.ActionPrint(context.Background(), nil, imageScanData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SBOM data available")
}

func TestActionPrint_CycloneDX_PostureScanWithImages(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		buildSeverityExceptionImageScanData(),
		buildSeverityExceptionImageScanData(),
	}

	tmp, err := os.CreateTemp("", "cyclonedx-posture-*.cdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	cp := NewCycloneDXPrinter()
	cp.writer = tmp
	require.NoError(t, cp.ActionPrint(context.Background(), cautils.NewOPASessionObjMock(), imageScanData))
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var documents []json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &documents))
	assert.Len(t, documents, 2, "a posture scan with --scan-images must emit one document per scanned image")
}
