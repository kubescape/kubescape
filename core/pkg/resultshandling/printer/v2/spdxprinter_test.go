package printer

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSPDXPrinter(t *testing.T) {
	sp := NewSPDXPrinter()
	assert.NotNil(t, sp)
}

func TestSetWriter_SPDX(t *testing.T) {
	sp := NewSPDXPrinter()
	sp.SetWriter(context.TODO(), "")
	assert.NotNil(t, sp.writer)
	sp.CloseWriter()
}

func TestSetWriter_SPDX_AppendsExtension(t *testing.T) {
	sp := NewSPDXPrinter()
	tmpDir := t.TempDir()
	sp.SetWriter(context.TODO(), tmpDir+"/report")
	defer sp.CloseWriter()

	assert.Contains(t, sp.writer.Name(), ".spdx.json")
}

func TestActionPrint_SPDX_ImageScan(t *testing.T) {
	imageScanData := []cautils.ImageScanData{buildSeverityExceptionImageScanData()}

	tmp, err := os.CreateTemp("", "spdx-imagescan-*.spdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	sp := NewSPDXPrinter()
	sp.writer = tmp
	sp.ActionPrint(context.Background(), nil, imageScanData)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc), "output must be valid JSON")
	version, ok := doc["spdxVersion"].(string)
	require.True(t, ok, "expected spdxVersion field")
	assert.True(t, strings.HasPrefix(version, "SPDX-"))
}

func TestActionPrint_SPDX_NonImageScan_NoOutput(t *testing.T) {
	tmp, err := os.CreateTemp("", "spdx-noimage-*.spdx.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	sp := NewSPDXPrinter()
	sp.writer = tmp
	sp.ActionPrint(context.Background(), cautils.NewOPASessionObjMock(), nil)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	assert.Empty(t, raw, "spdx-json must not write anything for a non-image scan")
}
