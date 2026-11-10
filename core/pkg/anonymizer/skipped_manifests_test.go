package anonymizer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	skippedParsePath  = "/home/alice/acme-payroll-repo/broken.yaml"
	skippedLockedPath = "/home/alice/acme-payroll-repo/locked.yaml"
	skippedLargePath  = `C:\Users\alice\acme-payroll-repo\huge.yaml`
)

// skippedManifestsFixture mirrors what the files loader records: a parse
// error without the path, a read error that embeds the raw path (an
// os.PathError), and a size error that embeds the %q-quoted path.
func skippedManifestsFixture() []cautils.SkippedManifest {
	return []cautils.SkippedManifest{
		{Path: skippedParsePath, Reason: "parse error: document 1: yaml: line 2: did not find expected ',' or ']'"},
		{Path: skippedLockedPath, Reason: "read error: open " + skippedLockedPath + ": permission denied"},
		{Path: skippedLargePath, Reason: "file too large: " + strconv.Quote(skippedLargePath) + " size 99 exceeds limit 10 bytes"},
	}
}

func skippedManifestsSession() *cautils.OPASessionObj {
	return &cautils.OPASessionObj{
		ResourcesResult:  map[string]resourcesresults.Result{},
		ResourceSource:   map[string]reporthandling.Source{},
		Metadata:         &reporthandlingv2.Metadata{},
		Report:           &reporthandlingv2.PostureReport{},
		SkippedManifests: skippedManifestsFixture(),
		ScanCoverage:     cautils.ScanCoverage{SkippedManifests: skippedManifestsFixture(), Degraded: true, CoverageScore: 90},
	}
}

// The parts of an original path that identify the user and project.
var skippedManifestSecrets = []string{"alice", "acme-payroll-repo", "broken.yaml", "locked.yaml", "huge.yaml"}

func assertNoSkippedManifestSecrets(t *testing.T, serialized, where string) {
	t.Helper()
	for _, secret := range skippedManifestSecrets {
		assert.NotContains(t, serialized, secret, "%s must not contain %q", where, secret)
	}
}

func TestApplyHidesSkippedManifestPaths(t *testing.T) {
	session := skippedManifestsSession()
	require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))

	for name, skipped := range map[string][]cautils.SkippedManifest{
		"ScanCoverage.SkippedManifests": session.ScanCoverage.SkippedManifests,
		"SkippedManifests":              session.SkippedManifests,
	} {
		encoded, err := json.Marshal(skipped)
		require.NoError(t, err)
		assertNoSkippedManifestSecrets(t, string(encoded), name)

		require.Len(t, skipped, 3, name)
		// Each path gets the deterministic pseudonym source paths get, so the
		// entries stay distinguishable and a file keeps one name everywhere.
		mapping := NewMappingTransformer()
		for i, original := range skippedManifestsFixture() {
			want, err := mapping.Transform("src", original.Path)
			require.NoError(t, err)
			assert.Equal(t, want, skipped[i].Path, name)
		}
		assert.NotEqual(t, skipped[0].Path, skipped[1].Path)
		assert.NotEqual(t, skipped[1].Path, skipped[2].Path)

		// The diagnostic survives; only the path inside it is replaced.
		assert.Equal(t, skippedManifestsFixture()[0].Reason, skipped[0].Reason, name)
		assert.Equal(t, "read error: open "+skipped[1].Path+": permission denied", skipped[1].Reason, name)
		assert.Equal(t, "file too large: "+strconv.Quote(skipped[2].Path)+" size 99 exceeds limit 10 bytes", skipped[2].Reason, name)
	}

	// The rest of the coverage block is not identifying and is kept.
	assert.True(t, session.ScanCoverage.Degraded)
	assert.Equal(t, float32(90), session.ScanCoverage.CoverageScore)
}

func TestApplyEncryptedEncryptsSkippedManifestPaths(t *testing.T) {
	session := skippedManifestsSession()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	require.NoError(t, ApplyEncrypted(&resultshandling.ResultsHandler{ScanData: session}, dek, []byte("01234567890123456789012345678901")))

	encoded, err := json.Marshal(session.ScanCoverage.SkippedManifests)
	require.NoError(t, err)
	assertNoSkippedManifestSecrets(t, string(encoded), "encrypted ScanCoverage.SkippedManifests")
	for _, skipped := range session.ScanCoverage.SkippedManifests {
		assert.True(t, strings.HasPrefix(skipped.Path, "ENC["), skipped.Path)
	}
	// The reason embeds the same ciphertext as the path it names.
	assert.Contains(t, session.ScanCoverage.SkippedManifests[1].Reason, session.ScanCoverage.SkippedManifests[1].Path)
}

// Without --hide the paths are the user's own debugging information and must
// reach the report unchanged.
func TestSkippedManifestPathsKeptWithoutHide(t *testing.T) {
	session := skippedManifestsSession()
	for name, output := range printSkippedManifestsReports(t, session) {
		for _, original := range skippedManifestsFixture() {
			// JSON and YAML escape backslashes, so compare a separator-free part.
			assert.Contains(t, output, filepath.Base(strings.ReplaceAll(original.Path, `\`, "/")), name)
		}
		assert.Contains(t, output, "acme-payroll-repo", name)
	}
}

func TestHiddenJSONAndYAMLReportsDoNotLeakSkippedManifestPaths(t *testing.T) {
	session := skippedManifestsSession()
	require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))
	for name, output := range printSkippedManifestsReports(t, session) {
		assert.Contains(t, output, "skippedManifests", name)
		assertNoSkippedManifestSecrets(t, output, name)
	}
}

// printSkippedManifestsReports renders session through the JSON and YAML
// printers and the programmatic JSON used for --submit and the API.
func printSkippedManifestsReports(t *testing.T, session *cautils.OPASessionObj) map[string]string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	outputs := map[string]string{}

	jsonPath := filepath.Join(dir, "report.json")
	jsonPrinter := printerv2.NewJsonPrinter()
	require.NoError(t, jsonPrinter.SetWriter(ctx, jsonPath))
	require.NoError(t, jsonPrinter.ActionPrint(ctx, session, nil))
	require.NoError(t, jsonPrinter.CloseWriter())

	yamlPath := filepath.Join(dir, "report.yaml")
	yamlPrinter := printerv2.NewYamlPrinter()
	require.NoError(t, yamlPrinter.SetWriter(ctx, yamlPath))
	require.NoError(t, yamlPrinter.ActionPrint(ctx, session, nil))
	require.NoError(t, yamlPrinter.CloseWriter())

	for name, path := range map[string]string{"json printer": jsonPath, "yaml printer": yamlPath} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		outputs[name] = string(data)
	}

	programmatic, err := (&resultshandling.ResultsHandler{ScanData: session}).ToJson()
	require.NoError(t, err)
	outputs["programmatic json"] = string(programmatic)
	return outputs
}

// A failed transformation must leave both skipped-manifest copies exactly as
// they were, like every other part of the session.
func TestTransformSessionRollsBackSkippedManifests(t *testing.T) {
	session := skippedManifestsSession()
	before, err := json.Marshal([]any{session.SkippedManifests, session.ScanCoverage})
	require.NoError(t, err)

	err = transformSession(session, nil, &selectiveFailTransformer{
		delegate: NewMappingTransformer(), failPrefix: "src", failValue: skippedLargePath,
	})
	require.ErrorIs(t, err, errInjectedTransform)

	after, err := json.Marshal([]any{session.SkippedManifests, session.ScanCoverage})
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}
