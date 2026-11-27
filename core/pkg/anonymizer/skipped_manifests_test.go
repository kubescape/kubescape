package anonymizer

import (
	"context"
	"encoding/json"
	"fmt"
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

// A multi-input scan skips an input whose ignore file can't be used, with the
// loader's error as the reason. That error names the ignore file, which for a
// file or a glob input is in the input's directory, not under the input path.
func TestApplyHidesTheIgnoreFileOfASkippedInput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "acme-payroll-repo")
	require.NoError(t, os.MkdirAll(root, 0o700))
	file := filepath.Join(root, "deploy.yaml")
	require.NoError(t, os.WriteFile(file, []byte("kind: Pod\n"), 0o600))
	ignoreFile := filepath.Join(root, cautils.IgnoreFileName)

	invalidPattern := func(t *testing.T) {
		require.NoError(t, os.RemoveAll(ignoreFile))
		require.NoError(t, os.WriteFile(ignoreFile, []byte("[\n"), 0o600))
	}
	// A directory is rejected portably, even when tests run as root.
	notAFile := func(t *testing.T) {
		require.NoError(t, os.RemoveAll(ignoreFile))
		require.NoError(t, os.Mkdir(ignoreFile, 0o700))
	}
	for _, tc := range []struct {
		name   string
		input  string
		setup  func(*testing.T)
		reason error
	}{
		{"file input, invalid pattern", file, invalidPattern, cautils.ErrInvalidIgnorePattern},
		{"file input, ignore file is a directory", file, notAFile, cautils.ErrIgnoreFileNotRegular},
		{"glob input, invalid pattern", filepath.Join(root, "*.yaml"), invalidPattern, cautils.ErrInvalidIgnorePattern},
		{"directory input, ignore file is a directory", root, notAFile, cautils.ErrIgnoreFileNotRegular},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			_, err := cautils.NewScanPathFilter(tc.input, nil, true)
			require.ErrorIs(t, err, tc.reason)
			// What GetResources records for the input.
			skipped := func() []cautils.SkippedManifest {
				return []cautils.SkippedManifest{{Path: tc.input, Reason: fmt.Sprintf("failed to load input: %v", err)}}
			}

			hidden := skippedManifestsSession()
			hidden.SkippedManifests, hidden.ScanCoverage.SkippedManifests = skipped(), skipped()
			require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: hidden}))

			encrypted := skippedManifestsSession()
			encrypted.SkippedManifests, encrypted.ScanCoverage.SkippedManifests = skipped(), skipped()
			dek := make([]byte, 32)
			require.NoError(t, ApplyEncrypted(&resultshandling.ResultsHandler{ScanData: encrypted}, dek, []byte("01234567890123456789012345678901")))

			for name, session := range map[string]*cautils.OPASessionObj{"--hide": hidden, "--encrypt": encrypted} {
				for _, entry := range [][]cautils.SkippedManifest{session.SkippedManifests, session.ScanCoverage.SkippedManifests} {
					encoded, err := json.Marshal(entry)
					require.NoError(t, err)
					assert.NotContains(t, string(encoded), "acme-payroll-repo", name)
					// The diagnostic survives: which file, and what is wrong with it.
					assert.Contains(t, entry[0].Reason, cautils.IgnoreFileName, name)
					assert.Contains(t, entry[0].Reason, tc.reason.Error(), name)
				}
			}
		})
	}
}

// The loader records the ignore file it read for a skipped input. The input
// can't always lead back to it: a repository cloned with a non-default depth,
// or a directory gone by now. The recorded path is hidden either way, and the
// report keeps no copy of it.
func TestApplyHidesTheRecordedIgnoreFileOfASkippedInput(t *testing.T) {
	clone := filepath.Join(t.TempDir(), "kubescape-clone-alice")
	ignoreFile := filepath.Join(clone, cautils.IgnoreFileName)
	skipped := func() []cautils.SkippedManifest {
		return []cautils.SkippedManifest{{
			Path:       "https://github.com/acme/payroll",
			Reason:     "failed to load input: " + ignoreFile + `: invalid exclusion pattern: "["`,
			IgnoreFile: ignoreFile,
		}}
	}
	dek := make([]byte, 32)
	for name, apply := range map[string]func(*resultshandling.ResultsHandler) error{
		"--hide": Apply,
		"--encrypt": func(handler *resultshandling.ResultsHandler) error {
			return ApplyEncrypted(handler, dek, []byte("01234567890123456789012345678901"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := skippedManifestsSession()
			session.SkippedManifests, session.ScanCoverage.SkippedManifests = skipped(), skipped()
			require.NoError(t, apply(&resultshandling.ResultsHandler{ScanData: session}))

			for _, entry := range [][]cautils.SkippedManifest{session.SkippedManifests, session.ScanCoverage.SkippedManifests} {
				require.Len(t, entry, 1)
				assert.NotContains(t, entry[0].Reason, "kubescape-clone-alice")
				assert.Contains(t, entry[0].Reason, cautils.IgnoreFileName)
				assert.Empty(t, entry[0].IgnoreFile)
			}
		})
	}
}

// Each path in a reason is replaced once. The pseudonym of an input named "src"
// contains "src", and must not be replaced again.
func TestApplyReplacesEachPathInASkippedReasonOnce(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.Mkdir("src", 0o700))
	ignoreFile := filepath.Join("src", cautils.IgnoreFileName)
	pseudonym, err := NewMappingTransformer().Transform("src", "src")
	require.NoError(t, err)
	hiddenIgnoreFile := pseudonym + string(filepath.Separator) + cautils.IgnoreFileName

	for name, tc := range map[string]struct{ reason, want string }{
		"ignore file": {
			reason: "failed to load input: " + ignoreFile + `: invalid exclusion pattern: "["`,
			want:   "failed to load input: " + hiddenIgnoreFile + `: invalid exclusion pattern: "["`,
		},
		"quoted ignore file": {
			reason: "failed to load input: " + strconv.Quote(ignoreFile) + " is a directory, not a file",
			want:   "failed to load input: " + strconv.Quote(hiddenIgnoreFile) + " is a directory, not a file",
		},
		"quoted input": {
			reason: "file too large: " + strconv.Quote("src") + " size 99 exceeds limit 10 bytes",
			want:   "file too large: " + strconv.Quote(pseudonym) + " size 99 exceeds limit 10 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			skipped := func() []cautils.SkippedManifest {
				return []cautils.SkippedManifest{{Path: "src", Reason: tc.reason}}
			}
			session := skippedManifestsSession()
			session.SkippedManifests, session.ScanCoverage.SkippedManifests = skipped(), skipped()
			require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))

			assert.Equal(t, pseudonym, session.SkippedManifests[0].Path)
			assert.Equal(t, tc.want, session.SkippedManifests[0].Reason)
			assert.Equal(t, tc.want, session.ScanCoverage.SkippedManifests[0].Reason)
		})
	}
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

// The Terraform resources left out of a scan are listed by address in the
// report. They are labels from the scanned configuration, so --hide and
// --encrypt replace them, as they do the path.
func TestApplyHidesTheSkippedTerraformResources(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme-payroll-repo")
	skipped := func() []cautils.SkippedManifest {
		return []cautils.SkippedManifest{{
			Path:      dir,
			Reason:    "2 Terraform resource(s) not scanned because they use values that can't be resolved; see scan logs for details",
			Resources: []string{"kubernetes_pod_v1.payments_gateway", "kubernetes_pod_v1.ledger"},
		}}
	}
	dek := make([]byte, 32)
	for name, apply := range map[string]func(*resultshandling.ResultsHandler) error{
		"--hide": Apply,
		"--encrypt": func(handler *resultshandling.ResultsHandler) error {
			return ApplyEncrypted(handler, dek, []byte("01234567890123456789012345678901"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := skippedManifestsSession()
			session.SkippedManifests, session.ScanCoverage.SkippedManifests = skipped(), skipped()
			require.NoError(t, apply(&resultshandling.ResultsHandler{ScanData: session}))

			for _, entry := range [][]cautils.SkippedManifest{session.SkippedManifests, session.ScanCoverage.SkippedManifests} {
				require.Len(t, entry, 1)
				encoded, err := json.Marshal(entry)
				require.NoError(t, err)
				for _, secret := range []string{"payments_gateway", "ledger", "acme-payroll-repo"} {
					assert.NotContains(t, string(encoded), secret, name)
				}
				// The count and the diagnostic survive, and the resources stay
				// distinguishable.
				require.Len(t, entry[0].Resources, 2, name)
				assert.NotEqual(t, entry[0].Resources[0], entry[0].Resources[1], name)
				assert.Contains(t, entry[0].Reason, "2 Terraform resource(s) not scanned", name)
			}
		})
	}
}

// Anonymizing a session leaves the resources of the session it was cloned from
// as they were, since the entries share the list.
func TestApplyDoesNotEditTheSkippedTerraformResourcesInPlace(t *testing.T) {
	resources := []string{"kubernetes_pod_v1.payments_gateway"}
	entries := []cautils.SkippedManifest{{Path: "/work/acme/infra", Reason: "1 Terraform resource(s) not scanned", Resources: resources}}

	require.NoError(t, transformSkippedManifests(entries, NewMappingTransformer()))
	assert.NotEqual(t, []string{"kubernetes_pod_v1.payments_gateway"}, entries[0].Resources)
	assert.Equal(t, []string{"kubernetes_pod_v1.payments_gateway"}, resources, "the original list is not edited")
}

// The resources are part of the report when nothing hides them.
func TestSkippedManifestResourcesArePartOfTheReport(t *testing.T) {
	skipped := cautils.SkippedManifest{
		Path:      "infra",
		Reason:    "1 Terraform resource(s) not scanned",
		Resources: []string{"kubernetes_pod_v1.web"},
	}
	encoded, err := json.Marshal(skipped)
	require.NoError(t, err)
	assert.JSONEq(t, `{"path":"infra","reason":"1 Terraform resource(s) not scanned","resources":["kubernetes_pod_v1.web"]}`, string(encoded))

	encoded, err = json.Marshal(cautils.SkippedManifest{Path: "broken.yaml", Reason: "invalid YAML"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"path":"broken.yaml","reason":"invalid YAML"}`, string(encoded), "other skips are unchanged")
}
