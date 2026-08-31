package reportcrypto_test

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptRepoReport produces a complete encrypted report whose repository
// metadata identifies repoName, using the supplied DEK.
func encryptRepoReport(t *testing.T, dek []byte, masterKey []byte, repoName string) []byte {
	t.Helper()

	session := &cautils.OPASessionObj{
		Metadata: &reporthandlingv2.Metadata{
			ContextMetadata: reporthandlingv2.ContextMetadata{
				RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
					Provider:  "github",
					Repo:      repoName,
					Owner:     "acme",
					Branch:    "main",
					RemoteURL: "https://github.com/acme/" + repoName + ".git",
					LastCommit: reporthandling.LastCommit{
						CommitterEmail: "engineer@acme.example",
						Message:        "release " + repoName,
					},
				},
			},
		},
		Report: &reporthandlingv2.PostureReport{},
	}

	handler := &resultshandling.ResultsHandler{ScanData: session}
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, masterKey))

	encrypted, err := handler.ToJson()
	require.NoError(t, err)

	return encrypted
}

func repoField(t *testing.T, report map[string]any, field string) string {
	t.Helper()

	metadata, ok := report["metadata"].(map[string]any)
	require.True(t, ok, "report has no metadata object")

	target, ok := metadata["targetMetadata"].(map[string]any)
	require.True(t, ok, "metadata has no targetMetadata object")

	repo, ok := target["gitRepoContextMetadata"].(map[string]any)
	require.True(t, ok, "targetMetadata has no gitRepoContextMetadata object")

	value, ok := repo[field].(string)
	require.True(t, ok, "gitRepoContextMetadata has no %q string", field)

	return value
}

func setRepoField(t *testing.T, report map[string]any, field, value string) {
	t.Helper()

	report["metadata"].(map[string]any)["targetMetadata"].(map[string]any)["gitRepoContextMetadata"].(map[string]any)[field] = value
}

// TestEncryptedFieldIsNotPortableBetweenReports is the end-to-end regression
// test for the interchangeable-ciphertext bug.
//
// Two reports are encrypted under one DEK - which the API permits, since
// ApplyEncrypted takes the key from its caller - and a single encrypted field is
// lifted out of the first and pasted into the second. Before ciphertexts were
// bound to a report, that spliced blob decrypted cleanly and authenticated, so
// `kubescape decrypt` reported the wrong repository with no indication that
// anything had been rewritten.
//
// On the unfixed code the decryption below succeeds and the assertion on
// "second-service" fails.
func TestEncryptedFieldIsNotPortableBetweenReports(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")

	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	firstJSON := encryptRepoReport(t, dek, masterKey, "first-service")
	secondJSON := encryptRepoReport(t, dek, masterKey, "second-service")

	var first, second map[string]any
	require.NoError(t, json.Unmarshal(firstJSON, &first))
	require.NoError(t, json.Unmarshal(secondJSON, &second))

	stolen := repoField(t, first, "repo")
	require.NotEqual(t, stolen, repoField(t, second, "repo"))

	// Sanity check that both reports really are sealed under the same DEK, so
	// the splice below fails on the binding rather than on the key.
	firstKey, err := reportcrypto.UnwrapReportKey(
		first["metadata"].(map[string]any)["encryptionMetadata"].(map[string]any)["encryptedDEK"].(string),
		masterKey,
	)
	require.NoError(t, err)

	secondKey, err := reportcrypto.UnwrapReportKey(
		second["metadata"].(map[string]any)["encryptionMetadata"].(map[string]any)["encryptedDEK"].(string),
		masterKey,
	)
	require.NoError(t, err)

	require.Equal(t, firstKey.DEK(), secondKey.DEK(), "test requires a shared DEK")
	require.NotEqual(t, firstKey.Binding(), secondKey.Binding())

	setRepoField(t, second, "repo", stolen)

	tampered, err := json.Marshal(second)
	require.NoError(t, err)

	_, err = reportcrypto.DecryptReport(tampered, masterKey)
	require.Error(t, err, "a field lifted from another report must not decrypt")

	// The untampered report must still round-trip, so the guard above is
	// rejecting the splice and not simply breaking decryption.
	decrypted, err := reportcrypto.DecryptReport(secondJSON, masterKey)
	require.NoError(t, err)

	var restored map[string]any
	require.NoError(t, json.Unmarshal(decrypted, &restored))
	assert.Equal(t, "second-service", repoField(t, restored, "repo"))
}
