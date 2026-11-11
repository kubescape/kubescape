package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixInfoValidateVerify(t *testing.T) {
	tests := []struct {
		name    string
		info    FixInfo
		wantErr string
	}{
		{name: "nothing set", info: FixInfo{}},
		{name: "verify alone", info: FixInfo{Verify: true}},
		{name: "verify with no-confirm and interactive", info: FixInfo{Verify: true, NoConfirm: true, Interactive: true}},
		{name: "verify with a controls configuration", info: FixInfo{Verify: true, ControlsConfig: "config.json"}},
		{name: "verify with Helm output, which is never applied", info: FixInfo{Verify: true, KustomizeDir: "./patches"}},

		{name: "verify with dry-run", info: FixInfo{Verify: true, DryRun: true},
			wantErr: "--verify cannot be combined with --dry-run: no fix is applied, so there is nothing to verify"},
		{name: "verify with output-dir", info: FixInfo{Verify: true, OutputDir: "./fixed"},
			wantErr: "--verify cannot be combined with --output-dir: the manifests are not changed, so a rescan would find every finding as it was"},
		{name: "verify with output-patch", info: FixInfo{Verify: true, OutputPatch: "remediation.patch"},
			wantErr: "--verify cannot be combined with --output-patch: the manifests are not changed, so a rescan would find every finding as it was"},
		{name: "verify with output-patch and no-confirm", info: FixInfo{Verify: true, OutputPatch: "remediation.patch", NoConfirm: true},
			wantErr: "--verify cannot be combined with --output-patch: the manifests are not changed, so a rescan would find every finding as it was"},

		{name: "a controls configuration without verify", info: FixInfo{ControlsConfig: "config.json"},
			wantErr: "--controls-config only applies to --verify: it is the controls configuration the verification rescan uses"},
		{name: "a blank controls configuration", info: FixInfo{Verify: true, ControlsConfig: "  "},
			wantErr: "--controls-config needs a file path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.ValidateVerify()

			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

// TestFixInfoOutputPatchAndVerifyAreRefusedFromBothSides: whichever validator a
// caller consults, the pair is refused, and the combination is refused by Verify
// even though OutputPatch alone is valid.
func TestFixInfoOutputPatchAndVerifyAreRefusedFromBothSides(t *testing.T) {
	info := FixInfo{Verify: true, OutputPatch: "remediation.patch"}

	assert.NoError(t, info.ValidateOutputPatch(), "a patch on its own is valid")
	assert.Error(t, info.ValidateVerify(), "but not together with --verify")
}

func TestFixInfoValidateOutputDir(t *testing.T) {
	tests := []struct {
		name      string
		outputDir string
		wantErr   string
	}{
		{name: "empty output-dir is allowed when not set", outputDir: ""},
		{name: "valid output-dir", outputDir: "/tmp/fixed"},
		{name: "relative output-dir", outputDir: "./fixed"},
		{name: "whitespace output-dir is refused", outputDir: "   ", wantErr: "--output-dir needs a directory path"},
		{name: "tab whitespace output-dir is refused", outputDir: "\t", wantErr: "--output-dir needs a directory path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := FixInfo{OutputDir: tt.outputDir}
			err := info.ValidateOutputDir()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestFixInfoValidateKustomizeDir(t *testing.T) {
	tests := []struct {
		name         string
		kustomizeDir string
		wantErr      string
	}{
		{name: "empty kustomize-dir is allowed when not set", kustomizeDir: ""},
		{name: "valid kustomize-dir", kustomizeDir: "/tmp/kust"},
		{name: "relative kustomize-dir", kustomizeDir: "./kust"},
		{name: "whitespace kustomize-dir is refused", kustomizeDir: "   ", wantErr: "--output-kustomize needs a directory path"},
		{name: "tab whitespace kustomize-dir is refused", kustomizeDir: "\t", wantErr: "--output-kustomize needs a directory path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := FixInfo{KustomizeDir: tt.kustomizeDir}
			err := info.ValidateKustomizeDir()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestFixInfoValidateOutputPatch(t *testing.T) {
	tests := []struct {
		name    string
		info    FixInfo
		wantErr string
	}{
		{name: "empty patch is allowed when not set", info: FixInfo{}},
		{name: "valid patch", info: FixInfo{OutputPatch: "remediation.patch"}},
		{name: "whitespace patch is refused", info: FixInfo{OutputPatch: "   "}, wantErr: "--output-patch needs a file path"},
		{name: "patch combined with output-dir", info: FixInfo{OutputPatch: "remediation.patch", OutputDir: "./fixed"},
			wantErr: "--output-patch cannot be combined with --output-dir: choose a patch or fixed copies"},
		{name: "patch combined with whitespace output-dir", info: FixInfo{OutputPatch: "remediation.patch", OutputDir: "  "},
			wantErr: "--output-patch cannot be combined with --output-dir: choose a patch or fixed copies"},
		{name: "patch combined with dry-run", info: FixInfo{OutputPatch: "remediation.patch", DryRun: true},
			wantErr: "--output-patch cannot be combined with --dry-run: exporting a patch already leaves the manifests untouched"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.ValidateOutputPatch()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
