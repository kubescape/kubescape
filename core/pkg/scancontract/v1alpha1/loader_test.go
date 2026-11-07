package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validContract = `
apiVersion: config.kubescape.io/v1alpha1
kind: ScanContract
metadata:
  name: payments-service
spec:
  minimumKubescapeVersion: v4.0.0
  defaultContract: developer
  contracts:
    developer:
      policy:
        frameworks: [nsa]
        controlsVersion: v2.0.307
      evaluation:
        controlTimeout: 30s
      output:
        formats: [pretty-printer]
    ci:
      policy:
        frameworks: [nsa]
        controlsVersion: v2.0.307
      scope:
        excludeNamespaces: [kube-system]
      evaluation:
        scanTimeout: 10m
        controlTimeout: 30s
      failure:
        severityAtLeast: high
        complianceBelow: 80
        coverageBelow: 95
        degradedPolicyInput: fail
      output:
        formats: [json, sarif]
        omitRawResources: true
`

func testOptions() LoadOptions {
	return LoadOptions{
		RunningVersion:      "v4.1.0",
		SupportedFormats:    []string{"pretty-printer", "json", "sarif"},
		SupportedSeverities: []string{"low", "medium", "high", "critical"},
	}
}

func TestLoadRejectsNullStringListEntries(t *testing.T) {
	for _, field := range []struct {
		name string
		old  string
		new  string
	}{
		{"frameworks", "frameworks: [nsa]", "frameworks: [null]"},
		{"controls", "frameworks: [nsa]", "controls: [null]"},
		{"include namespaces", "excludeNamespaces: [kube-system]", "includeNamespaces: [null]"},
		{"exclude namespaces", "excludeNamespaces: [kube-system]", "excludeNamespaces: [null]"},
		{"formats", "formats: [pretty-printer]", "formats: [null]"},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, entry := range []string{"null", "~", "", "json, null", "&empty null, *empty"} {
				t.Run(entry, func(t *testing.T) {
					// A blank block-sequence entry is also a YAML null.
					replacement := strings.Replace(field.new, "[null]", "["+entry+"]", 1)
					if entry == "" {
						replacement = strings.Replace(field.new, "[null]", "\n          -", 1)
					}
					input := strings.Replace(validContract, field.old, replacement, 1)
					_, err := Load([]byte(input), testOptions())
					require.ErrorContains(t, err, "null entry")
				})
			}
		})
	}
}

func TestLoadPreservesExplicitEmptyStringLists(t *testing.T) {
	input := strings.ReplaceAll(validContract, "frameworks: [nsa]", "frameworks: []\n        controls: []")
	input = strings.ReplaceAll(input, "excludeNamespaces: [kube-system]", "includeNamespaces: []\n        excludeNamespaces: []")
	input = strings.ReplaceAll(input, "formats: [json, sarif]", "formats: []")
	options := testOptions()
	options.ContractName = "ci"
	selected, err := Load([]byte(input), options)
	require.NoError(t, err)
	// Explicit empty lists must remain distinct from omitted fields.
	require.NotNil(t, selected.Contract.Policy.Frameworks)
	assert.Empty(t, *selected.Contract.Policy.Frameworks)
	require.NotNil(t, selected.Contract.Policy.Controls)
	assert.Empty(t, *selected.Contract.Policy.Controls)
	require.NotNil(t, selected.Contract.Scope.IncludeNamespaces)
	assert.Empty(t, *selected.Contract.Scope.IncludeNamespaces)
	require.NotNil(t, selected.Contract.Scope.ExcludeNamespaces)
	assert.Empty(t, *selected.Contract.Scope.ExcludeNamespaces)
	require.NotNil(t, selected.Contract.Output.Formats)
	assert.Empty(t, *selected.Contract.Output.Formats)
}

func TestLoadRejectsAliasToNullStringListEntry(t *testing.T) {
	input := strings.Replace(validContract, "defaultContract: developer", "defaultContract: &empty null", 1)
	input = strings.Replace(input, "frameworks: [nsa]", "frameworks: [*empty]", 1)
	options := testOptions()
	options.ContractName = "developer"
	_, err := Load([]byte(input), options)
	require.ErrorContains(t, err, "null entry")
}

func TestLoadSelectsAndDigestsContract(t *testing.T) {
	selected, err := Load([]byte(validContract), testOptions())
	require.NoError(t, err)

	assert.Equal(t, "developer", selected.ContractName)
	assert.Equal(t, DigestSchema, selected.DigestSchema)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, selected.ContractDigest)
	require.NotNil(t, selected.Contract.Policy)
	require.NotNil(t, selected.Contract.Policy.Frameworks)
	assert.Equal(t, []string{"nsa"}, []string(*selected.Contract.Policy.Frameworks))
}

func TestLoadContractOverride(t *testing.T) {
	options := testOptions()
	options.ContractName = "ci"
	selected, err := Load([]byte(validContract), options)
	require.NoError(t, err)

	assert.Equal(t, "ci", selected.ContractName)
	require.NotNil(t, selected.Contract.Failure)
	require.NotNil(t, selected.Contract.Failure.CoverageBelow)
	assert.Equal(t, 95.0, *selected.Contract.Failure.CoverageBelow)
}

func TestLoadRejectsUnknownFieldsStrictly(t *testing.T) {
	input := strings.Replace(validContract, "        frameworks: [nsa]", "        frameworkz: [nsa]", 1)
	_, err := Load([]byte(input), testOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "field frameworkz not found")
}

func TestLoadChecksVersionBeforeFullSchema(t *testing.T) {
	input := strings.Replace(validContract, APIVersion, "config.kubescape.io/v2", 1)
	input = strings.Replace(input, "        frameworks: [nsa]", "        frameworkz: [nsa]", 1)
	_, err := Load([]byte(input), testOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported apiVersion")
	assert.NotContains(t, err.Error(), "frameworkz")
}

func TestLoadRejectsNewerMinimumVersion(t *testing.T) {
	options := testOptions()
	options.RunningVersion = "v4.0.0"
	input := strings.Replace(validContract, "v4.0.0", "v4.1.0", 1)
	_, err := Load([]byte(input), options)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires Kubescape v4.1.0 or newer")
}

func TestLoadSkipsCompatibilityForNonReleaseBuilds(t *testing.T) {
	for _, runningVersion := range []string{"", "dev", "unknown", "(devel)"} {
		t.Run(runningVersion, func(t *testing.T) {
			options := testOptions()
			options.RunningVersion = runningVersion
			_, err := Load([]byte(validContract), options)
			require.NoError(t, err)
		})
	}
}

func TestLoadRejectsDuplicateKeys(t *testing.T) {
	input := strings.Replace(validContract, "  name: payments-service", "  name: payments-service\n  name: duplicate", 1)
	_, err := Load([]byte(input), testOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already defined")
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	_, err := Load([]byte(validContract+"\n---\n{}\n"), testOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one YAML document")
}

func TestLoadValidatesAllNamedContracts(t *testing.T) {
	input := strings.Replace(validContract, "        coverageBelow: 95", "        coverageBelow: 101", 1)
	_, err := Load([]byte(input), testOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.contracts.ci.failure.coverageBelow")
}

func TestDigestIgnoresUnusedContractsAndYAMLFormatting(t *testing.T) {
	options := testOptions()
	first, err := Load([]byte(validContract), options)
	require.NoError(t, err)

	withoutCI := validContract[:strings.Index(validContract, "    ci:\n")]
	second, err := Load([]byte(withoutCI), options)
	require.NoError(t, err)

	assert.Equal(t, first.ContractDigest, second.ContractDigest)
}

func TestDigestPreservesExplicitEmptyValues(t *testing.T) {
	withOmittedControls := validContract
	withEmptyControls := strings.Replace(validContract, "        frameworks: [nsa]", "        frameworks: [nsa]\n        controls: []", 1)

	omitted, err := Load([]byte(withOmittedControls), testOptions())
	require.NoError(t, err)
	explicit, err := Load([]byte(withEmptyControls), testOptions())
	require.NoError(t, err)

	assert.NotEqual(t, omitted.ContractDigest, explicit.ContractDigest)
}

func TestDigestEffectiveRunUsesSeparateStableDomain(t *testing.T) {
	first, err := DigestEffectiveRun(struct {
		Effective map[string]any `json:"effective"`
	}{Effective: map[string]any{"coverageBelow": 95, "severityAtLeast": "high"}})
	require.NoError(t, err)
	second, err := DigestEffectiveRun(struct {
		Effective map[string]any `json:"effective"`
	}{Effective: map[string]any{"severityAtLeast": "high", "coverageBelow": 95}})
	require.NoError(t, err)
	changed, err := DigestEffectiveRun(struct {
		Effective map[string]any `json:"effective"`
	}{Effective: map[string]any{"coverageBelow": 90, "severityAtLeast": "high"}})
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.NotEqual(t, first, changed)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, first)
}

func TestLoadRejectsInvalidContractValues(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{"unknown format", "formats: [json, sarif]", "formats: [json, xml]", "unsupported format"},
		{"unknown severity", "severityAtLeast: high", "severityAtLeast: urgent", "unsupported; supported severities"},
		{"negative timeout", "controlTimeout: 30s", "controlTimeout: -1s", "must be zero or positive"},
		{"both namespace scopes", "excludeNamespaces: [kube-system]", "includeNamespaces: [default]\n        excludeNamespaces: [kube-system]", "cannot both be set"},
		{"unknown degradation mode", "degradedPolicyInput: fail", "degradedPolicyInput: warn", "supported values: allow, fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Replace(validContract, tt.old, tt.replacement, 1)
			_, err := Load([]byte(input), testOptions())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadFile_Valid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contract.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validContract), 0o600))

	selected, err := LoadFile(path, testOptions())
	require.NoError(t, err)
	require.NotNil(t, selected)
	assert.Equal(t, "payments-service", selected.Metadata.Name)
	assert.Equal(t, "developer", selected.ContractName)
}

func TestLoadFile_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

	_, err := LoadFile(path, testOptions())
	require.Error(t, err)
	assert.ErrorContains(t, err, "contract document is empty")
}

func TestLoadFile_OversizedFileRejected(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "oversized.yaml")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxContractBytes+1))
	require.NoError(t, f.Close())

	_, err = LoadFile(filePath, testOptions())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContractTooLarge)
}

func TestLoadFile_DirectoryRejected(t *testing.T) {
	_, err := LoadFile(t.TempDir(), testOptions())
	require.Error(t, err)
	assert.ErrorContains(t, err, "is a directory, not a file")
}

func TestLoadFile_NonRegularFileRejected(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err == nil {
		_, err := LoadFile("/dev/null", testOptions())
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrContractNotRegular)
	}
}
