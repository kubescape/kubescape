package reportcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A container image report carries the scanned image in each control's
// evidence. The value is a copy of the resource field, so it is encrypted by
// --encrypt and must be restored like any other resource field.
func TestDecryptReportRestoresControlEvidence(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)

	report := decodeTestObject(t, fixture.data)
	results, ok := report["results"].([]any)
	require.True(t, ok, "fixture report must have a results array")
	require.NotEmpty(t, results)
	result, ok := results[0].(map[string]any)
	require.True(t, ok)
	controls, ok := result["controls"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, controls)
	control, ok := controls[0].(map[string]any)
	require.True(t, ok)

	encryptedImage, err := EncryptString("nginx:1.25", fixture.dek)
	require.NoError(t, err)
	control["evidence"] = []any{
		map[string]any{
			"path":  "spec.containers[0].image",
			"value": encryptedImage,
		},
	}

	decrypted, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.NoError(t, err)

	decryptedReport := decodeTestObject(t, decrypted)
	decryptedResults, ok := decryptedReport["results"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, decryptedResults)
	decryptedResult, ok := decryptedResults[0].(map[string]any)
	require.True(t, ok)
	decryptedControls, ok := decryptedResult["controls"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, decryptedControls)
	decryptedControl, ok := decryptedControls[0].(map[string]any)
	require.True(t, ok)
	evidence, ok := decryptedControl["evidence"].([]any)
	require.True(t, ok)
	require.Len(t, evidence, 1)
	entry, ok := evidence[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "spec.containers[0].image", entry["path"])
	assert.Equal(t, "nginx:1.25", entry["value"])
}
