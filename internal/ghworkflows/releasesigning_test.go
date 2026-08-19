// Package ghworkflows holds repository-hygiene tests. These ones guard the
// supply-chain controls a release claims to carry.
//
// A release published 29 assets and not one signature: .goreleaser.yaml
// declared `docker_signs` for container images and no `signs` block at all, so
// nothing signed the binaries or the checksum manifest. Meanwhile install.sh
// and install.ps1 both told users, in a comment, to "use the cosign signature
// or build provenance attestation" instead of trusting the checksum alone -
// advice that could not be followed, because half of it did not exist.
//
// Nothing failed. A missing signature is not a build error, and the two files
// that disagreed sit in different languages with no link between them, so the
// only way to notice was to go looking at the published assets. Worse, both
// files were invisible to CI: .goreleaser.yaml matches 00-pr-scanner.yaml's
// "**.yaml" deny-list and install.sh matches "**.sh", so a PR touching only
// them ran nothing.
//
// These tests turn the install scripts' promises into assertions against the
// config that has to keep them, pin the provenance attestation that already
// works so it cannot be dropped by a later edit, and - because a guard nobody
// runs is the failure this whole area is about - assert that repo-hygiene.yaml
// still schedules them for every file they cover.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
package ghworkflows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	goreleaserConfigName = ".goreleaser.yaml"

	// releaseWorkflowName is the only workflow that publishes assets, so it is
	// the only place build provenance can be attested from.
	releaseWorkflowName = "02-release.yaml"

	// hygieneWorkflowName schedules this package. Its `paths` allow-list is the
	// only reason a PR touching .goreleaser.yaml or install.sh runs any check at
	// all: 00-pr-scanner.yaml's deny-list ignores "**.yaml" and "**.sh".
	hygieneWorkflowName = "repo-hygiene.yaml"

	// provenanceAction attests the released binaries. It stores the attestation
	// in GitHub's attestation index rather than as a release asset, which is why
	// a release legitimately carries no .intoto.jsonl file while still being
	// covered - `gh attestation verify` resolves it by digest.
	provenanceAction = "actions/attest-build-provenance"

	// checksumArtifacts is GoReleaser's selector for the checksum manifest.
	// Signing that one file transitively covers every asset it lists.
	checksumArtifacts = "checksum"

	// artifactPlaceholder is what GoReleaser substitutes with the artifact path
	// when it expands a `signature` or `certificate` template.
	artifactPlaceholder = "${artifact}"

	// cosignVerifyCmd and provenanceVerifyCmd are the commands the install
	// scripts must actually spell out. Naming the mechanism without one of these
	// is the exact state that shipped: advice that cannot be followed.
	cosignVerifyCmd     = "cosign verify-blob"
	provenanceVerifyCmd = "gh attestation verify"
)

// installScripts are the entry points that tell a user how to verify a
// download. Whatever they promise has to exist.
var installScripts = []string{"install.sh", "install.ps1"}

// guardedFiles are the files these tests read. Every one of them must be in
// repo-hygiene.yaml's allow-list, or the guard covering it never runs on the PR
// that breaks it. Kept next to the tests so adding a guard forces the question.
var guardedFiles = append([]string{
	goreleaserConfigName,
	filepath.Join(".github", "workflows", releaseWorkflowName),
	filepath.Join("internal", "ghworkflows", "releasesigning_test.go"),
}, installScripts...)

// goreleaserSign is the subset of a `signs` / `docker_signs` entry these tests
// assert on. Unknown keys are tolerated on purpose: GoReleaser supports many
// optional fields (env, if, output), and a strict decoder would turn adopting
// one of them into a spurious failure here.
//
// Stdin is decoded because it is the tell for keyed signing: docker_signs pipes
// the key password through it, so a copy of that block into `signs` carries it
// along with --key.
type goreleaserSign struct {
	ID          string   `yaml:"id"`
	Cmd         string   `yaml:"cmd"`
	Args        []string `yaml:"args"`
	Signature   string   `yaml:"signature"`
	Certificate string   `yaml:"certificate"`
	Artifacts   string   `yaml:"artifacts"`
	Stdin       string   `yaml:"stdin"`
}

type goreleaserConfig struct {
	Signs    []goreleaserSign `yaml:"signs"`
	Checksum struct {
		NameTemplate string `yaml:"name_template"`
	} `yaml:"checksum"`
}

// releaseWorkflow is the subset of 02-release.yaml these tests assert on.
// Job-level `permissions` is a mapping; the workflow-level one is the scalar
// "read-all" and is deliberately not decoded here.
type releaseWorkflow struct {
	Jobs map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name string `yaml:"name"`
			Uses string `yaml:"uses"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// hygieneWorkflow reads repo-hygiene.yaml's pull_request allow-list.
// gopkg.in/yaml.v3 follows the YAML 1.2 core schema, so `on:` unmarshals as the
// plain string "on" and the struct tag below matches it.
type hygieneWorkflow struct {
	On struct {
		PullRequest struct {
			Paths []string `yaml:"paths"`
		} `yaml:"pull_request"`
	} `yaml:"on"`
}

func goreleaserConfigPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(repoRoot(t), goreleaserConfigName)
}

// loadGoreleaserConfig reads and parses the release config, surfacing the
// parser's own message on failure.
func loadGoreleaserConfig(t *testing.T) goreleaserConfig {
	t.Helper()

	configPath := goreleaserConfigPath(t)
	content, err := os.ReadFile(configPath)
	require.NoErrorf(t, err, "cannot read %s", configPath)

	var config goreleaserConfig
	require.NoErrorf(t, yaml.Unmarshal(content, &config),
		"%s is not valid YAML; GoReleaser would fail the release run", configPath)

	return config
}

// loadWorkflow reads one workflow through the same helper the README tests use,
// so both stay in step with the workflows actually on disk.
func loadWorkflow(t *testing.T, name string, into any) {
	t.Helper()

	content, ok := workflowFiles(t)[name]
	require.Truef(t, ok, "%s is missing; these guards need updating to follow it", name)
	require.NoErrorf(t, yaml.Unmarshal(content, into), "%s is not valid YAML", name)
}

// readInstallScript returns one install script's text.
func readInstallScript(t *testing.T, script string) string {
	t.Helper()

	scriptPath := filepath.Join(repoRoot(t), script)
	content, err := os.ReadFile(scriptPath)
	require.NoErrorf(t, err, "cannot read %s", scriptPath)

	return string(content)
}

// blobSigners returns the `signs` entries that cover the checksum manifest.
// docker_signs is deliberately not consulted: it signs container images, which
// nothing a user downloads from the releases page is served by.
func blobSigners(config goreleaserConfig) []goreleaserSign {
	var signers []goreleaserSign
	for _, sign := range config.Signs {
		if sign.Artifacts == checksumArtifacts {
			signers = append(signers, sign)
		}
	}
	return signers
}

// requireBlobSigners fails with the regression's own explanation rather than a
// bare empty-slice message, and stops the tests that would otherwise pass
// vacuously by iterating over nothing.
func requireBlobSigners(t *testing.T, config goreleaserConfig) []goreleaserSign {
	t.Helper()

	signers := blobSigners(config)
	require.NotEmptyf(t, signers,
		"%s declares no `signs` entry with `artifacts: %s`. docker_signs covers container images only, "+
			"so the published binaries and checksums.sha256 would ship unsigned and the install scripts' "+
			"verification instructions would have nothing to verify against",
		goreleaserConfigName, checksumArtifacts)

	return signers
}

// expandArtifact resolves a GoReleaser signature/certificate template against
// the artifact it will be applied to, giving the published asset name.
func expandArtifact(template, artifact string) string {
	return strings.ReplaceAll(template, artifactPlaceholder, artifact)
}

// pathCoveredBy reports whether a workflow `paths` entry selects file. It
// handles the two forms this repository uses - an exact path and a "dir/**"
// prefix - and deliberately nothing else, so an unrecognised pattern reads as
// "not covered" rather than as a false pass.
func pathCoveredBy(pattern, file string) bool {
	if pattern == file {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return strings.HasPrefix(file, prefix+"/")
	}
	return false
}

// TestGoreleaserSignsTheChecksumManifest is the direct regression test: without
// a `signs` block the release carries checksum-only integrity, which a
// compromised release or GitHub account defeats completely, because the
// manifest and the binary it describes are fetched from the same place.
func TestGoreleaserSignsTheChecksumManifest(t *testing.T) {
	for _, signer := range requireBlobSigners(t, loadGoreleaserConfig(t)) {
		assert.Equalf(t, "cosign", signer.Cmd,
			"signs entry %q must use cosign; the install scripts document %q", signer.ID, cosignVerifyCmd)

		// Both outputs have to be uploaded. A signature without the certificate
		// proves only that someone signed the manifest, not that this
		// repository's release workflow did.
		assert.NotEmptyf(t, signer.Signature, "signs entry %q publishes no signature file", signer.ID)
		assert.NotEmptyf(t, signer.Certificate,
			"signs entry %q publishes no certificate; without it a verifier cannot pin the signing identity "+
				"and the signature degrades to 'signed by someone'", signer.ID)
	}
}

// TestGoreleaserSigningArgsProduceTheDeclaredOutputs closes the gap between what
// GoReleaser is told to upload and what cosign is told to write. `signature:`
// and `certificate:` only name files for upload; if args do not ask cosign to
// emit them the release fails at publish time, long after the change that broke
// it merged. --yes matters for a different reason: without it cosign waits for
// confirmation on a runner with no terminal and the release job hangs.
func TestGoreleaserSigningArgsProduceTheDeclaredOutputs(t *testing.T) {
	for _, signer := range requireBlobSigners(t, loadGoreleaserConfig(t)) {
		args := strings.Join(signer.Args, " ")

		assert.Containsf(t, args, "sign-blob",
			"signs entry %q does not run `cosign sign-blob`, so it signs no release asset", signer.ID)

		if signer.Signature != "" {
			assert.Containsf(t, args, "--output-signature",
				"signs entry %q declares a signature file but never tells cosign to write one", signer.ID)
		}
		if signer.Certificate != "" {
			assert.Containsf(t, args, "--output-certificate",
				"signs entry %q declares a certificate file but never tells cosign to write one; "+
					"GoReleaser then fails the release looking for a file that was never created", signer.ID)
		}

		assert.Truef(t, strings.Contains(args, "--yes") || strings.Contains(args, " -y"),
			"signs entry %q omits --yes; cosign prompts for confirmation and the release job hangs", signer.ID)
	}
}

// TestGoreleaserBlobSigningIsKeyless guards the choice, not just the presence.
// docker_signs uses the COSIGN_PRIVATE_KEY_V1 pair, but that public key is
// published nowhere a user running install.sh can reach, so a keyed blob
// signature would be unverifiable by the people it exists to protect. Keyless
// binds the signature to the release workflow's OIDC identity instead.
func TestGoreleaserBlobSigningIsKeyless(t *testing.T) {
	for _, signer := range requireBlobSigners(t, loadGoreleaserConfig(t)) {
		for _, arg := range signer.Args {
			assert.Falsef(t, arg == "--key" || strings.HasPrefix(arg, "--key="),
				"signs entry %q signs with a key (%s), but this repository publishes no cosign public key. "+
					"Either drop --key to sign keyless, or publish the public key and update the install scripts",
				signer.ID, arg)
		}

		// docker_signs pipes the key password through stdin. Finding that here
		// means the keyed block was copied rather than the keyless one written.
		assert.Emptyf(t, signer.Stdin,
			"signs entry %q pipes a key password through stdin, which only a keyed signature needs", signer.ID)
	}
}

// TestSignedAssetNamesMatchTheDocumentedCommands is the cross-check the original
// bug had no equivalent of: config and docs agreeing that a signature exists,
// but disagreeing on what it is called. Renaming `signature` to "${artifact}.sig
// nature" would leave every other assertion here green while every command the
// install scripts print fails on a missing file.
func TestSignedAssetNamesMatchTheDocumentedCommands(t *testing.T) {
	config := loadGoreleaserConfig(t)

	manifest := config.Checksum.NameTemplate
	require.NotEmptyf(t, manifest, "%s sets no checksum name_template", goreleaserConfigName)
	require.NotContainsf(t, manifest, "{{", "checksum name_template %q is templated; "+
		"the install scripts hardcode a literal file name and cannot follow it", manifest)

	// Every asset the signing config publishes has to be named by every script
	// that tells a user to verify with it.
	//
	// The empty check is not redundant with TestGoreleaserSignsTheChecksumManifest:
	// an unset template expands to "", and strings.Contains is true for "", so
	// without it a dropped `certificate:` would make this test pass by asserting
	// nothing at all.
	var published []string
	for _, signer := range requireBlobSigners(t, config) {
		for field, template := range map[string]string{
			"signature":   signer.Signature,
			"certificate": signer.Certificate,
		} {
			asset := expandArtifact(template, manifest)
			require.NotEmptyf(t, asset,
				"signs entry %q declares no %s, so there is no published asset name to hold the install "+
					"scripts to", signer.ID, field)
			published = append(published, asset)
		}
	}

	for _, script := range installScripts {
		text := readInstallScript(t, script)
		assert.Containsf(t, text, manifest,
			"%s never names the checksum manifest %q that %s publishes", script, manifest, goreleaserConfigName)

		for _, asset := range published {
			assert.Containsf(t, text, asset,
				"%s documents verification but never names %q, which is what %s actually publishes",
				script, asset, goreleaserConfigName)
		}
	}
}

// TestInstallScriptsDocumentRunnableVerification is the guard that would have
// caught the original bug from the other direction, and it is deliberately
// unconditional. An earlier draft only checked consistency *if* a script
// mentioned cosign, which meant deleting the advice made the test pass - the
// same silence the bug shipped behind.
func TestInstallScriptsDocumentRunnableVerification(t *testing.T) {
	for _, script := range installScripts {
		text := readInstallScript(t, script)

		// Naming the mechanism is not enough; a user has to be able to run it.
		assert.Containsf(t, text, cosignVerifyCmd,
			"%s does not show a runnable %q command. Checksum verification alone binds the binary to a "+
				"manifest fetched from the same place, so it does not survive a compromised release",
			script, cosignVerifyCmd)

		// A keyless signature is only meaningful if the verifier is told which
		// identity to expect; --certificate-identity-regexp is what does that.
		assert.Containsf(t, text, "--certificate-identity-regexp",
			"%s documents cosign verification without pinning the signing identity, "+
				"so any valid Sigstore certificate would satisfy it", script)
		assert.Containsf(t, text, "--certificate-oidc-issuer",
			"%s documents cosign verification without pinning the OIDC issuer", script)

		assert.Containsf(t, text, provenanceVerifyCmd,
			"%s does not show a runnable %q command; the provenance attestation the release records "+
				"is then undiscoverable, because it is not published as a release asset",
			script, provenanceVerifyCmd)
		assert.Containsf(t, text, "--repo kubescape/kubescape",
			"%s documents %q without scoping it to this repository", script, provenanceVerifyCmd)
	}
}

// TestReleaseWorkflowAttestsBuildProvenance pins the control that already
// works. The attestation lives in GitHub's attestation index rather than in the
// release assets, so its absence would be invisible on the releases page - the
// same way the missing signature was.
func TestReleaseWorkflowAttestsBuildProvenance(t *testing.T) {
	var workflow releaseWorkflow
	loadWorkflow(t, releaseWorkflowName, &workflow)

	release, ok := workflow.Jobs["release"]
	require.Truef(t, ok, "%s has no `release` job", releaseWorkflowName)

	var attests bool
	for _, step := range release.Steps {
		if strings.HasPrefix(step.Uses, provenanceAction+"@") {
			attests = true
			break
		}
	}
	require.Truef(t, attests,
		"%s no longer runs %s; released binaries would carry no provenance and %q - which the install "+
			"scripts document - would fail for every user",
		releaseWorkflowName, provenanceAction, provenanceVerifyCmd)

	// Both permissions are required and neither fails loudly when dropped:
	// without them the attest step errors at the end of an otherwise successful
	// release, and keyless signing loses the OIDC token it needs.
	assert.Equal(t, "write", release.Permissions["attestations"],
		"the `release` job needs `attestations: write` to record provenance")
	assert.Equal(t, "write", release.Permissions["id-token"],
		"the `release` job needs `id-token: write` for keyless cosign signing and for provenance")
}

// TestRepoHygieneWatchesTheFilesTheseTestsGuard is the guard on the guard.
//
// Everything above only runs because repo-hygiene.yaml allow-lists the files it
// covers. 00-pr-scanner.yaml skips a PR whose every file matches its deny-list,
// and ".goreleaser.yaml" matches "**.yaml" while "install.sh" matches "**.sh" -
// so dropping an entry here does not fail anything, it just quietly stops these
// tests from ever running on the PR that breaks release signing. That is the
// same shape as the Dependabot outage: a check that was off, reported nowhere.
func TestRepoHygieneWatchesTheFilesTheseTestsGuard(t *testing.T) {
	var workflow hygieneWorkflow
	loadWorkflow(t, hygieneWorkflowName, &workflow)

	patterns := workflow.On.PullRequest.Paths
	require.NotEmptyf(t, patterns,
		"%s declares no pull_request `paths`; it would run on every PR or none, and either way it is no "+
			"longer the targeted allow-list the other workflow's deny-list needs", hygieneWorkflowName)

	for _, file := range guardedFiles {
		// Workflow globs are POSIX-separated regardless of the host OS.
		file = filepath.ToSlash(file)

		var covered bool
		for _, pattern := range patterns {
			if pathCoveredBy(pattern, file) {
				covered = true
				break
			}
		}

		assert.Truef(t, covered,
			"%s is asserted on by this package but is not in %s's pull_request paths (%v), so a PR changing "+
				"only that file runs no check at all", file, hygieneWorkflowName, patterns)
	}
}
