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
