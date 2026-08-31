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

func writeImageScanJSON(t *testing.T, imageScanData []cautils.ImageScanData) []byte {
	t.Helper()

	tmp, err := os.CreateTemp("", "json-image-scan-*.json")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	jp := NewJsonPrinter()
	jp.writer = tmp
	require.NoError(t, jp.ActionPrint(context.Background(), nil, imageScanData))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return raw
}

func TestJsonPrinter_ImageScan_SingleImageKeepsBareDocument(t *testing.T) {
	raw := writeImageScanJSON(t, []cautils.ImageScanData{buildSeverityExceptionImageScanData()})

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Contains(t, doc, "matches")
}

func TestJsonPrinter_ImageScan_ReportsEveryImage(t *testing.T) {
	first := buildSeverityExceptionImageScanData()
	first.Image = "first-image:latest"
	second := buildSeverityExceptionImageScanData()
	second.Image = "second-image:latest"

	raw := writeImageScanJSON(t, []cautils.ImageScanData{first, second})

	var documents []struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(raw, &documents))
	require.Len(t, documents, 2, "every scanned image must reach the json report")

	for _, doc := range documents {
		var ids []string
		for _, m := range doc.Matches {
			ids = append(ids, m.Vulnerability.ID)
		}
		assert.Contains(t, ids, "CVE-KEPT")
	}
}
