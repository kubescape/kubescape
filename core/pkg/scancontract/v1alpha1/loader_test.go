package v1alpha1

import (
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

func TestLoadSelectsAndDigestsContract(t *testing.T) {
	selected, err := Load([]byte(validContract), testOptions())
	require.NoError(t, err)

	assert.Equal(t, "developer", selected.ContractName)
	assert.Equal(t, DigestSchema, selected.DigestSchema)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, selected.ContractDigest)
	require.NotNil(t, selected.Contract.Policy)
	require.NotNil(t, selected.Contract.Policy.Frameworks)
	assert.Equal(t, []string{"nsa"}, *selected.Contract.Policy.Frameworks)
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
