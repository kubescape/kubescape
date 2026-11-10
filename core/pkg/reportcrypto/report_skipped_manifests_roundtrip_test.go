package reportcrypto_test

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skippedManifestsForRoundTrip() []cautils.SkippedManifest {
	locked := "/home/alice/acme-payroll-repo/locked.yaml"
	huge := `C:\Users\alice\acme-payroll-repo\huge.yaml`
	return []cautils.SkippedManifest{
		{Path: "/home/alice/acme-payroll-repo/broken.yaml", Reason: "parse error: document 1: yaml: line 2: did not find expected ',' or ']'"},
		{Path: locked, Reason: "read error: open " + locked + ": permission denied"},
		{Path: huge, Reason: "file too large: " + strconv.Quote(huge) + " size 99 exceeds limit 10 bytes"},
	}
}

func encryptedReportWithSkippedManifests(t *testing.T) []byte {
	t.Helper()
	session := &cautils.OPASessionObj{
		ResourcesResult:  map[string]resourcesresults.Result{},
		ResourceSource:   map[string]reporthandling.Source{},
		Metadata:         &reporthandlingv2.Metadata{},
		Report:           &reporthandlingv2.PostureReport{},
		SkippedManifests: skippedManifestsForRoundTrip(),
		ScanCoverage:     cautils.ScanCoverage{SkippedManifests: skippedManifestsForRoundTrip(), Degraded: true},
	}
	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(exceptionTestMasterKey)))
	encrypted, err := handler.ToJson()
	require.NoError(t, err)
	return encrypted
}

func TestEncryptedReportRoundTripRestoresSkippedManifests(t *testing.T) {
	encryptedJSON := encryptedReportWithSkippedManifests(t)
	for _, secret := range []string{"alice", "acme-payroll-repo", "broken.yaml", "locked.yaml", "huge.yaml"} {
		assert.NotContains(t, string(encryptedJSON), secret)
	}

	// Fields from a newer version must survive decryption.
	var encrypted map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &encrypted))
	coverage := encrypted["scanCoverage"].(map[string]any)
	coverage["futureCoverageField"] = "kept-coverage"
	coverage["skippedManifests"].([]any)[0].(map[string]any)["futureSkipField"] = "kept-skip"
	encryptedJSON, err := json.Marshal(encrypted)
	require.NoError(t, err)

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
	require.NoError(t, err)

	var decrypted struct {
		ScanCoverage cautils.ScanCoverage `json:"scanCoverage"`
	}
	require.NoError(t, json.Unmarshal(decryptedJSON, &decrypted))
	want := skippedManifestsForRoundTrip()
	require.Len(t, decrypted.ScanCoverage.SkippedManifests, len(want))
	for i := range want {
		assert.Equal(t, want[i].Path, decrypted.ScanCoverage.SkippedManifests[i].Path)
	}
	assert.Equal(t, want[0].Reason, decrypted.ScanCoverage.SkippedManifests[0].Reason)
	assert.Equal(t, want[1].Reason, decrypted.ScanCoverage.SkippedManifests[1].Reason)
	// The quoted path comes back as the path between quotes: exact for any
	// path %q leaves unescaped, but a Windows path's escaped backslashes are
	// not reproduced.
	assert.Equal(t, `file too large: "`+want[2].Path+`" size 99 exceeds limit 10 bytes`, decrypted.ScanCoverage.SkippedManifests[2].Reason)
	assert.True(t, decrypted.ScanCoverage.Degraded)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &raw))
	rawCoverage := raw["scanCoverage"].(map[string]any)
	assert.Equal(t, "kept-coverage", rawCoverage["futureCoverageField"])
	assert.Equal(t, "kept-skip", rawCoverage["skippedManifests"].([]any)[0].(map[string]any)["futureSkipField"])
}

func TestDecryptReportRejectsMalformedSkippedManifestCiphertext(t *testing.T) {
	encryptedJSON := encryptedReportWithSkippedManifests(t)
	for field, corrupt := range map[string]func(t *testing.T, skip map[string]any){
		"path": func(t *testing.T, skip map[string]any) {
			path := skip["path"].(string)
			require.True(t, strings.HasPrefix(path, "ENC["), "path must be encrypted: %q", path)
			skip["path"] = strings.TrimSuffix(path, "]")
		},
		"reason": func(t *testing.T, skip map[string]any) {
			reason := skip["reason"].(string)
			require.Contains(t, reason, "ENC[", "reason must embed the encrypted path")
			end := strings.Index(reason, "]")
			skip["reason"] = reason[:end-6] + "AAAA" + reason[end:]
		},
	} {
		t.Run(field, func(t *testing.T) {
			var report map[string]any
			require.NoError(t, json.Unmarshal(encryptedJSON, &report))
			corrupt(t, report["scanCoverage"].(map[string]any)["skippedManifests"].([]any)[1].(map[string]any))
			tampered, err := json.Marshal(report)
			require.NoError(t, err)

			out, err := reportcrypto.DecryptReport(tampered, []byte(exceptionTestMasterKey))
			assert.Error(t, err)
			assert.Nil(t, out)
		})
	}
}

// A report without skipped manifests decrypts as before.
func TestEncryptedReportRoundTripWithoutSkippedManifests(t *testing.T) {
	session := &cautils.OPASessionObj{
		ResourcesResult: map[string]resourcesresults.Result{},
		ResourceSource:  map[string]reporthandling.Source{},
		Metadata:        &reporthandlingv2.Metadata{},
		Report:          &reporthandlingv2.PostureReport{},
	}
	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(exceptionTestMasterKey)))
	encrypted, err := handler.ToJson()
	require.NoError(t, err)
	_, err = reportcrypto.DecryptReport(encrypted, []byte(exceptionTestMasterKey))
	require.NoError(t, err)
}
