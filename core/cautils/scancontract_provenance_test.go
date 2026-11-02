package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDigester struct {
	path   string
	digest string
	ok     bool
}

func (s stubDigester) ConsumedFileDigest() (string, string, bool) {
	return s.path, s.digest, s.ok
}

func ptr[T any](v T) *T { return &v }

func sampleEffectiveSettings() *reporthandlingv2.ScanContractEffectiveSettings {
	return &reporthandlingv2.ScanContractEffectiveSettings{
		Policy: &reporthandlingv2.ScanContractPolicy{
			Frameworks: []string{"mitre"},
			Controls:   []string{"C-0002"},
		},
		Scope: &reporthandlingv2.ScanContractScope{
			IncludeNamespaces: []string{"production"},
			ExcludeNamespaces: []string{"development"},
		},
		Evaluation: &reporthandlingv2.ScanContractEvaluation{
			ScanTimeout:    "10m",
			ControlTimeout: "30s",
		},
		Failure: &reporthandlingv2.ScanContractFailure{
			SeverityAtLeast:     ptr("high"),
			ComplianceBelow:     ptr(80.0),
			CoverageBelow:       ptr(90.0),
			DegradedPolicyInput: ptr(true),
		},
		Output: &reporthandlingv2.ScanContractOutput{
			Formats:          []string{"json", "sarif"},
			OmitRawResources: ptr(true),
		},
	}
}

func TestFinalizeScanContractMetadata_NilContract(t *testing.T) {
	assert.Nil(t, finalizeScanContractMetadata(&ScanInfo{}, nil))
}

func TestFinalizeScanContractMetadata_ReplacesExecutedPolicyAndCopiesSlices(t *testing.T) {
	scanInfo := &ScanInfo{
		ScanContract: &reporthandlingv2.ScanContractMetadata{
			AllowedSections: []string{"policy"},
			DeniedSections:  []string{"output"},
			RunnerInputs: []reporthandlingv2.ScanContractRunnerInput{
				{Role: "exceptions", Source: "exceptions.json", Digest: "sha256:one"},
			},
			Effective: sampleEffectiveSettings(),
		},
	}

	got := finalizeScanContractMetadata(scanInfo, []PolicyIdentifier{
		{Identifier: "nsa", Kind: apisv1.KindFramework},
		{Identifier: "C-0001", Kind: apisv1.KindControl},
	})
	require.NotNil(t, got)
	require.NotNil(t, got.Effective)
	require.NotNil(t, got.Effective.Policy)
	assert.Equal(t, []string{"nsa"}, got.Effective.Policy.Frameworks)
	assert.Equal(t, []string{"C-0001"}, got.Effective.Policy.Controls)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, got.EffectiveRunDigest)

	got.AllowedSections[0] = "mutated"
	got.DeniedSections[0] = "mutated"
	got.RunnerInputs[0].Digest = "sha256:mutated"
	assert.Equal(t, "policy", scanInfo.ScanContract.AllowedSections[0])
	assert.Equal(t, "output", scanInfo.ScanContract.DeniedSections[0])
	assert.Equal(t, "sha256:one", scanInfo.ScanContract.RunnerInputs[0].Digest)
	assert.Equal(t, []string{"mitre"}, scanInfo.ScanContract.Effective.Policy.Frameworks)
	assert.Equal(t, []string{"C-0002"}, scanInfo.ScanContract.Effective.Policy.Controls)
}

func TestFinalizeScanContractMetadata_KeepsPolicyWhenIdentifiersEmpty(t *testing.T) {
	scanInfo := &ScanInfo{
		ScanContract: &reporthandlingv2.ScanContractMetadata{
			Effective: sampleEffectiveSettings(),
		},
	}

	got := finalizeScanContractMetadata(scanInfo, nil)
	require.NotNil(t, got.Effective.Policy)
	assert.Equal(t, []string{"mitre"}, got.Effective.Policy.Frameworks)
	assert.Equal(t, []string{"C-0002"}, got.Effective.Policy.Controls)
}

func TestCloneEffectiveSettings(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.Nil(t, cloneEffectiveSettings(nil))
	})

	t.Run("mutating clone does not change original", func(t *testing.T) {
		original := sampleEffectiveSettings()
		clone := cloneEffectiveSettings(original)
		require.NotNil(t, clone)

		clone.Policy.Frameworks[0] = "mutated"
		clone.Policy.Controls[0] = "mutated"
		clone.Scope.IncludeNamespaces[0] = "mutated"
		clone.Scope.ExcludeNamespaces[0] = "mutated"
		clone.Evaluation.ScanTimeout = "1s"
		*clone.Failure.SeverityAtLeast = "low"
		*clone.Failure.ComplianceBelow = 1
		*clone.Failure.CoverageBelow = 2
		*clone.Failure.DegradedPolicyInput = false
		clone.Output.Formats[0] = "mutated"
		*clone.Output.OmitRawResources = false

		assert.Equal(t, "mitre", original.Policy.Frameworks[0])
		assert.Equal(t, "C-0002", original.Policy.Controls[0])
		assert.Equal(t, "production", original.Scope.IncludeNamespaces[0])
		assert.Equal(t, "development", original.Scope.ExcludeNamespaces[0])
		assert.Equal(t, "10m", original.Evaluation.ScanTimeout)
		assert.Equal(t, "high", *original.Failure.SeverityAtLeast)
		assert.Equal(t, 80.0, *original.Failure.ComplianceBelow)
		assert.Equal(t, 90.0, *original.Failure.CoverageBelow)
		assert.True(t, *original.Failure.DegradedPolicyInput)
		assert.Equal(t, "json", original.Output.Formats[0])
		assert.True(t, *original.Output.OmitRawResources)
	})
}

func TestCaptureScanContractRunnerInput(t *testing.T) {
	tests := []struct {
		name    string
		source  any
		wantOK  bool
		wantSrc string
	}{
		{name: "not a digester", source: "controls.json"},
		{name: "digest unavailable", source: stubDigester{path: "controls.json", digest: "sha256:abc", ok: false}},
		{name: "success sanitizes path", source: stubDigester{path: "controls.json", digest: "sha256:abc", ok: true}, wantOK: true, wantSrc: "controls.json"},
		{name: "parent path is external", source: stubDigester{path: "../controls.json", digest: "sha256:abc", ok: true}, wantOK: true, wantSrc: "external"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CaptureScanContractRunnerInput("controlsConfig", tt.source)
			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Equal(t, reporthandlingv2.ScanContractRunnerInput{}, got)
				return
			}
			assert.Equal(t, "controlsConfig", got.Role)
			assert.Equal(t, tt.wantSrc, got.Source)
			assert.Equal(t, "sha256:abc", got.Digest)
		})
	}
}

func TestRecordScanContractRunnerInput(t *testing.T) {
	scanInfo := &ScanInfo{ScanContract: &reporthandlingv2.ScanContractMetadata{}}

	_, ok := RecordScanContractRunnerInput(scanInfo, "controlsConfig", "not-a-digester")
	assert.False(t, ok)
	assert.Empty(t, scanInfo.ScanContract.RunnerInputs)

	got, ok := RecordScanContractRunnerInput(scanInfo, "controlsConfig", stubDigester{
		path: "controls.json", digest: "sha256:abc", ok: true,
	})
	require.True(t, ok)
	assert.Equal(t, "controlsConfig", got.Role)
	require.Len(t, scanInfo.ScanContract.RunnerInputs, 1)
	assert.Equal(t, got, scanInfo.ScanContract.RunnerInputs[0])
}

func TestRecordCachedScanContractRunnerInput(t *testing.T) {
	t.Run("no-op on incomplete input", func(t *testing.T) {
		scanInfo := &ScanInfo{ScanContract: &reporthandlingv2.ScanContractMetadata{}}
		RecordCachedScanContractRunnerInput(nil, reporthandlingv2.ScanContractRunnerInput{Role: "exceptions", Digest: "sha256:one"})
		RecordCachedScanContractRunnerInput(&ScanInfo{}, reporthandlingv2.ScanContractRunnerInput{Role: "exceptions", Digest: "sha256:one"})
		RecordCachedScanContractRunnerInput(scanInfo, reporthandlingv2.ScanContractRunnerInput{Digest: "sha256:one"})
		RecordCachedScanContractRunnerInput(scanInfo, reporthandlingv2.ScanContractRunnerInput{Role: "exceptions"})
		assert.Empty(t, scanInfo.ScanContract.RunnerInputs)
	})

	t.Run("replaces same role and sorts new roles", func(t *testing.T) {
		scanInfo := &ScanInfo{ScanContract: &reporthandlingv2.ScanContractMetadata{}}
		RecordCachedScanContractRunnerInput(scanInfo, reporthandlingv2.ScanContractRunnerInput{
			Role: "exceptions", Source: "old.json", Digest: "sha256:old",
		})
		RecordCachedScanContractRunnerInput(scanInfo, reporthandlingv2.ScanContractRunnerInput{
			Role: "controlsConfig", Source: "controls.json", Digest: "sha256:controls",
		})
		RecordCachedScanContractRunnerInput(scanInfo, reporthandlingv2.ScanContractRunnerInput{
			Role: "exceptions", Source: "new.json", Digest: "sha256:new",
		})

		require.Len(t, scanInfo.ScanContract.RunnerInputs, 2)
		assert.Equal(t, "controlsConfig", scanInfo.ScanContract.RunnerInputs[0].Role)
		assert.Equal(t, "exceptions", scanInfo.ScanContract.RunnerInputs[1].Role)
		assert.Equal(t, "new.json", scanInfo.ScanContract.RunnerInputs[1].Source)
		assert.Equal(t, "sha256:new", scanInfo.ScanContract.RunnerInputs[1].Digest)
	})
}

func TestSafeContractRunnerInputSource(t *testing.T) {
	assert.Equal(t, ".kubescape/controls.json", safeContractRunnerInputSource(".kubescape/controls.json"))
	assert.Equal(t, "external", safeContractRunnerInputSource("../controls.json"))
	assert.Equal(t, "external", safeContractRunnerInputSource(filepath.Join(t.TempDir(), "controls.json")))

	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, "controls.json", safeContractRunnerInputSource(filepath.Join(workingDirectory, "controls.json")))
}

var _ getter.ConsumedFileDigester = stubDigester{}
