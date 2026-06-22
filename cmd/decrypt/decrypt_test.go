package decrypt

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptCommand_PreservesUnknownFields(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	masterKey := []byte("12345678901234567890123456789012")

	encryptedRepo, err := reportcrypto.EncryptString(
		"kubescape",
		dek,
	)
	require.NoError(t, err)

	wrappedDEK, err := reportcrypto.WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	report := map[string]any{
		"resourceLabels": map[string]any{
			"team": "platform",
		},
		"scanCoverage": map[string]any{
			"all": true,
		},
		"metadata": map[string]any{
			"targetMetadata": map[string]any{
				"gitRepoContextMetadata": map[string]any{
					"repo": encryptedRepo,
				},
			},
			"encryptionMetadata": map[string]any{
				"encryptedDEK": wrappedDEK,
			},
		},
	}

	data, err := json.Marshal(report)
	require.NoError(t, err)

	tmp, err := os.CreateTemp("", "encrypted-*.json")
	require.NoError(t, err)

	defer os.Remove(tmp.Name())

	_, err = tmp.Write(data)
	require.NoError(t, err)

	require.NoError(t, tmp.Close())

	t.Setenv(
		"KUBESCAPE_MASTER_KEY",
		string(masterKey),
	)

	oldStdout := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	cmd := GetDecryptCommand()

	err = cmd.RunE(
		cmd,
		[]string{tmp.Name()},
	)

	require.NoError(t, err)

	require.NoError(t, w.Close())

	os.Stdout = oldStdout

	var buf bytes.Buffer

	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	var output map[string]any

	err = json.Unmarshal(
		buf.Bytes(),
		&output,
	)
	require.NoError(t, err)

	assert.Contains(
		t,
		output,
		"resourceLabels",
	)

	assert.Contains(
		t,
		output,
		"scanCoverage",
	)

	metadata :=
		output["metadata"].(map[string]any)

	targetMetadata :=
		metadata["targetMetadata"].(map[string]any)

	repoMetadata :=
		targetMetadata["gitRepoContextMetadata"].(map[string]any)

	assert.Equal(
		t,
		"kubescape",
		repoMetadata["repo"],
	)
}
