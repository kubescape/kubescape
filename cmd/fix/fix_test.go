package fix

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFixCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetFixCmd function
	fixCmd := GetFixCmd(mockKubescape)

	assert.Equal(t, "fix <report output file>", fixCmd.Use)

	err := fixCmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage := "report output file is required"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = fixCmd.RunE(&cobra.Command{}, []string{"random-file.json"})
	assert.Nil(t, err)
}

// Goes through Execute, not RunE, so Cobra's argument validation runs.
func TestFixCmdArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		// Non-nil: SetArgs(nil) makes Execute fall back to os.Args.
		{name: "no report", args: []string{}, wantErr: "report output file is required"},
		{name: "empty report", args: []string{""}, wantErr: "report output file cannot be empty"},
		{name: "blank report", args: []string{"   "}, wantErr: "report output file cannot be empty"},
		{name: "one report", args: []string{"report.json"}},
		{name: "extra report", args: []string{"a.json", "b.json"}, wantErr: "accepts at most 1 arg(s), received 2"},
		{name: "post-renderer without kustomize", args: []string{"report.json", "--output-post-renderer", "./patches"}, wantErr: "--output-post-renderer requires --output-kustomize"},
		{name: "post-renderer with kustomize", args: []string{"report.json", "--output-kustomize", "./patches", "--output-post-renderer", "./patches"}},
		{name: "empty output-dir", args: []string{"report.json", "--output-dir", ""}, wantErr: "--output-dir needs a directory path"},
		{name: "blank output-dir", args: []string{"report.json", "--output-dir", "   "}, wantErr: "--output-dir needs a directory path"},
		{name: "empty output-dir with equals", args: []string{"report.json", "--output-dir="}, wantErr: "--output-dir needs a directory path"},
		{name: "empty output-kustomize", args: []string{"report.json", "--output-kustomize", ""}, wantErr: "--output-kustomize needs a directory path"},
		{name: "blank output-kustomize", args: []string{"report.json", "--output-kustomize", "   "}, wantErr: "--output-kustomize needs a directory path"},
		{name: "empty output-kustomize with equals", args: []string{"report.json", "--output-kustomize="}, wantErr: "--output-kustomize needs a directory path"},
		{name: "empty output-post-renderer", args: []string{"report.json", "--output-post-renderer", ""}, wantErr: "--output-post-renderer needs a directory path"},
		{name: "blank output-post-renderer", args: []string{"report.json", "--output-post-renderer", "   "}, wantErr: "--output-post-renderer needs a directory path"},
		{name: "empty output-post-renderer with equals", args: []string{"report.json", "--output-post-renderer="}, wantErr: "--output-post-renderer needs a directory path"},
		{name: "empty base-path", args: []string{"report.json", "--base-path", ""}, wantErr: "--base-path needs a directory path"},
		{name: "blank base-path", args: []string{"report.json", "--base-path", "   "}, wantErr: "--base-path needs a directory path"},
		{name: "empty base-path with equals", args: []string{"report.json", "--base-path="}, wantErr: "--base-path needs a directory path"},
		{name: "empty container-profile", args: []string{"report.json", "--container-profile", ""}, wantErr: "--container-profile needs a file path"},
		{name: "blank container-profile", args: []string{"report.json", "--container-profile", "   "}, wantErr: "--container-profile needs a file path"},
		{name: "empty container-profile with equals", args: []string{"report.json", "--container-profile="}, wantErr: "--container-profile needs a file path"},
		{name: "empty output-patch", args: []string{"report.json", "--output-patch", ""}, wantErr: "--output-patch needs a file path"},
		{name: "blank output-patch", args: []string{"report.json", "--output-patch", "   "}, wantErr: "--output-patch needs a file path"},
		{name: "empty output-patch with equals", args: []string{"report.json", "--output-patch="}, wantErr: "--output-patch needs a file path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixCmd := GetFixCmd(&mocks.MockIKubescape{})
			fixCmd.SetArgs(tt.args)
			fixCmd.SetOut(io.Discard)
			fixCmd.SetErr(io.Discard)

			err := fixCmd.Execute()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestValidateControlSelection(t *testing.T) {
	tests := []struct {
		name    string
		fixInfo metav1.FixInfo
		wantErr string
	}{
		{name: "no filters", fixInfo: metav1.FixInfo{}},
		{name: "populated filters", fixInfo: metav1.FixInfo{IncludeControls: []string{"C-0016"}, SkipControls: []string{"C-0017"}}},
		{name: "empty include entry", fixInfo: metav1.FixInfo{IncludeControls: []string{"C-0016", " "}}, wantErr: "--include-controls contains an empty control identifier"},
		{name: "empty skip entry", fixInfo: metav1.FixInfo{SkipControls: []string{""}}, wantErr: "--skip-controls contains an empty control identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateControlSelection(&tt.fixInfo)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

type spyKubescape struct {
	mocks.MockIKubescape
	fixCalled bool
	received  *metav1.FixInfo
}

func (s *spyKubescape) Fix(info *metav1.FixInfo) error {
	s.fixCalled = true
	copy := *info
	copy.IncludeControls = append([]string(nil), info.IncludeControls...)
	copy.SkipControls = append([]string(nil), info.SkipControls...)
	s.received = &copy
	return nil
}

func TestFixCmdControlSelectionFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     string
		wantFixCall bool
		wantInclude []string
		wantSkip    []string
		wantReport  string
	}{
		{
			name:        "no control selection flags",
			args:        []string{"report.json"},
			wantFixCall: true,
			wantReport:  "report.json",
		},
		{
			name:        "single include control",
			args:        []string{"report.json", "--include-controls", "C-0016"},
			wantFixCall: true,
			wantInclude: []string{"C-0016"},
			wantReport:  "report.json",
		},
		{
			name:        "multiple include controls comma-separated",
			args:        []string{"report.json", "--include-controls", "C-0016,C-0017"},
			wantFixCall: true,
			wantInclude: []string{"C-0016", "C-0017"},
			wantReport:  "report.json",
		},
		{
			name:        "multiple include controls repeated flags",
			args:        []string{"report.json", "--include-controls", "C-0016", "--include-controls", "C-0017"},
			wantFixCall: true,
			wantInclude: []string{"C-0016", "C-0017"},
			wantReport:  "report.json",
		},
		{
			name:        "single skip control",
			args:        []string{"report.json", "--skip-controls", "C-0018"},
			wantFixCall: true,
			wantSkip:    []string{"C-0018"},
			wantReport:  "report.json",
		},
		{
			name:        "multiple skip controls comma-separated",
			args:        []string{"report.json", "--skip-controls", "C-0018,C-0019"},
			wantFixCall: true,
			wantSkip:    []string{"C-0018", "C-0019"},
			wantReport:  "report.json",
		},
		{
			name:        "multiple skip controls repeated flags",
			args:        []string{"report.json", "--skip-controls", "C-0018", "--skip-controls", "C-0019"},
			wantFixCall: true,
			wantSkip:    []string{"C-0018", "C-0019"},
			wantReport:  "report.json",
		},
		{
			name:        "both include and skip controls",
			args:        []string{"report.json", "--include-controls", "C-0016,C-0017", "--skip-controls", "C-0018"},
			wantFixCall: true,
			wantInclude: []string{"C-0016", "C-0017"},
			wantSkip:    []string{"C-0018"},
			wantReport:  "report.json",
		},
		{
			name:        "empty include control identifier via whitespace returns error and does not call fix",
			args:        []string{"report.json", "--include-controls", " "},
			wantErr:     "--include-controls contains an empty control identifier",
			wantFixCall: false,
		},
		{
			name:        "empty include control identifier via trailing comma returns error and does not call fix",
			args:        []string{"report.json", "--include-controls", "C-0016,"},
			wantErr:     "--include-controls contains an empty control identifier",
			wantFixCall: false,
		},
		{
			name:        "empty skip control identifier via whitespace returns error and does not call fix",
			args:        []string{"report.json", "--skip-controls", " "},
			wantErr:     "--skip-controls contains an empty control identifier",
			wantFixCall: false,
		},
		{
			name:        "empty skip control identifier via trailing comma returns error and does not call fix",
			args:        []string{"report.json", "--skip-controls", "C-0018,"},
			wantErr:     "--skip-controls contains an empty control identifier",
			wantFixCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyKubescape{}
			cmd := GetFixCmd(spy)
			cmd.SetArgs(tt.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.False(t, spy.fixCalled, "IKubescape.Fix should not be called when validation fails")
				assert.Nil(t, spy.received)
				return
			}

			assert.NoError(t, err)
			assert.True(t, spy.fixCalled, "IKubescape.Fix should be called")
			if assert.NotNil(t, spy.received) {
				assert.Equal(t, tt.wantReport, spy.received.ReportFile)
				assert.Equal(t, tt.wantInclude, spy.received.IncludeControls)
				assert.Equal(t, tt.wantSkip, spy.received.SkipControls)
			}
		})
	}
}

func TestGetFixCmd_HonorsOutputWriter(t *testing.T) {
	spy := &spyKubescape{}
	fixCmd := GetFixCmd(spy)
	var buf bytes.Buffer
	fixCmd.SetOut(&buf)
	fixCmd.SetArgs([]string{"report.json"})

	err := fixCmd.Execute()
	require.NoError(t, err)
	require.NotNil(t, spy.received)
	assert.Same(t, &buf, spy.received.Writer)
}

func TestGetFixCmd_NilKubescape(t *testing.T) {
	fixCmd := GetFixCmd(nil)
	fixCmd.SilenceUsage = true
	fixCmd.SilenceErrors = true
	fixCmd.SetArgs([]string{"report.json"})

	err := fixCmd.Execute()
	require.EqualError(t, err, "uninitialized kubescape interface")
}

func TestFixCmdOutputPatchFlag(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   string
		wantPatch string
	}{
		{name: "not given", args: []string{"report.json"}},
		{name: "a patch file", args: []string{"report.json", "--output-patch", "remediation.patch"}, wantPatch: "remediation.patch"},
		{name: "with no-confirm", args: []string{"report.json", "--output-patch", "remediation.patch", "--no-confirm"}, wantPatch: "remediation.patch"},
		{name: "with interactive", args: []string{"report.json", "--output-patch", "remediation.patch", "-i"}, wantPatch: "remediation.patch"},
		{name: "with control selection", args: []string{"report.json", "--output-patch", "remediation.patch", "--include-controls", "C-0016"}, wantPatch: "remediation.patch"},
		{name: "with output-kustomize", args: []string{"report.json", "--output-patch", "remediation.patch", "--output-kustomize", "./patches"}, wantPatch: "remediation.patch"},
		{name: "blank path", args: []string{"report.json", "--output-patch", " "}, wantErr: "--output-patch needs a file path"},
		// An unset shell variable gives an empty path. Treated as "not given" it
		// would fix the manifests in place, which --no-confirm would not stop.
		{name: "empty path", args: []string{"report.json", "--output-patch", ""}, wantErr: "--output-patch needs a file path"},
		{name: "empty path with equals", args: []string{"report.json", "--output-patch="}, wantErr: "--output-patch needs a file path"},
		{name: "empty path with no-confirm", args: []string{"report.json", "--no-confirm", "--output-patch", ""}, wantErr: "--output-patch needs a file path"},
		{name: "with output-dir", args: []string{"report.json", "--output-patch", "remediation.patch", "--output-dir", "./fixed"}, wantErr: "--output-patch cannot be combined with --output-dir: choose a patch or fixed copies"},
		{name: "with dry-run", args: []string{"report.json", "--output-patch", "remediation.patch", "--dry-run"}, wantErr: "--output-patch cannot be combined with --dry-run: exporting a patch already leaves the manifests untouched"},
		{name: "with verify", args: []string{"report.json", "--output-patch", "remediation.patch", "--verify"}, wantErr: "--verify cannot be combined with --output-patch: the manifests are not changed, so a rescan would find every finding as it was"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyKubescape{}
			cmd := GetFixCmd(spy)
			cmd.SetArgs(tt.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()

			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.False(t, spy.fixCalled, "a refused combination must not reach IKubescape.Fix")
				return
			}
			require.NoError(t, err)
			require.True(t, spy.fixCalled)
			assert.Equal(t, tt.wantPatch, spy.received.OutputPatch)
		})
	}
}

func TestFixCmdOutputPatchIsDocumented(t *testing.T) {
	cmd := GetFixCmd(&mocks.MockIKubescape{})

	flag := cmd.PersistentFlags().Lookup("output-patch")
	require.NotNil(t, flag, "the flag must be registered")
	assert.Contains(t, flag.Usage, "unified diff")
	assert.Contains(t, flag.Usage, "never modified")
	assert.Contains(t, cmd.Example, "--output-patch remediation.patch")
	assert.Contains(t, cmd.Example, "git apply")
}

func TestFixCmdVerifyFlag(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantErr    string
		wantVerify bool
	}{
		{name: "not given", args: []string{"report.json"}},
		{name: "given", args: []string{"report.json", "--verify"}, wantVerify: true},
		{name: "explicitly off", args: []string{"report.json", "--verify=false"}},
		{name: "with no-confirm", args: []string{"report.json", "--verify", "--no-confirm"}, wantVerify: true},
		{name: "with interactive", args: []string{"report.json", "--verify", "-i"}, wantVerify: true},
		{name: "with control selection", args: []string{"report.json", "--verify", "--include-controls", "C-0016"}, wantVerify: true},
		{name: "with output-kustomize", args: []string{"report.json", "--verify", "--output-kustomize", "./patches"}, wantVerify: true},
		{name: "with dry-run", args: []string{"report.json", "--verify", "--dry-run"}, wantErr: "--verify cannot be combined with --dry-run: no fix is applied, so there is nothing to verify"},
		{name: "with output-dir", args: []string{"report.json", "--verify", "--output-dir", "./fixed"}, wantErr: "--verify cannot be combined with --output-dir: the manifests are not changed, so a rescan would find every finding as it was"},
		{name: "with output-patch", args: []string{"report.json", "--verify", "--output-patch", "remediation.patch"}, wantErr: "--verify cannot be combined with --output-patch: the manifests are not changed, so a rescan would find every finding as it was"},
		{name: "with output-patch, either order", args: []string{"report.json", "--output-patch", "remediation.patch", "--verify"}, wantErr: "--verify cannot be combined with --output-patch: the manifests are not changed, so a rescan would find every finding as it was"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyKubescape{}
			cmd := GetFixCmd(spy)
			cmd.SetArgs(tt.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()

			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.False(t, spy.fixCalled, "a refused combination must not reach IKubescape.Fix")
				return
			}
			require.NoError(t, err)
			require.True(t, spy.fixCalled)
			assert.Equal(t, tt.wantVerify, spy.received.Verify)
		})
	}
}

// failingKubescape is a Fix that fails the way a verification that could not
// confirm every fix does.
type failingKubescape struct {
	mocks.MockIKubescape
	err error
}

func (f *failingKubescape) Fix(*metav1.FixInfo) error { return f.err }

// TestFixCmdVerifyFailureIsANonZeroExit: the command hands Fix's error on
// unchanged, and an error is what ends the process with exit code 1.
func TestFixCmdVerifyFailureIsANonZeroExit(t *testing.T) {
	failure := errors.New("verification did not confirm every fix: 1 still failing, 1 unverified")
	cmd := GetFixCmd(&failingKubescape{err: failure})
	cmd.SetArgs([]string{"report.json", "--verify"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()

	require.ErrorIs(t, err, failure)
	assert.Equal(t, 1, shared.ExitCode(err))

	spy := &spyKubescape{}
	ok := GetFixCmd(spy)
	ok.SetArgs([]string{"report.json", "--verify"})
	ok.SetOut(io.Discard)
	ok.SetErr(io.Discard)
	assert.Equal(t, 0, shared.ExitCode(ok.Execute()), "a verification that confirmed everything exits 0")
}

func TestFixCmdVerifyIsDocumented(t *testing.T) {
	cmd := GetFixCmd(&mocks.MockIKubescape{})

	flag := cmd.PersistentFlags().Lookup("verify")
	require.NotNil(t, flag, "the flag must be registered")
	assert.Equal(t, "false", flag.DefValue)
	assert.Contains(t, flag.Usage, "rescan")
	assert.Contains(t, flag.Usage, "never a resolution")
	assert.Contains(t, flag.Usage, "exceptions", "the settings the rescan cannot reproduce are named")
	assert.Contains(t, cmd.Example, "--verify")
}

func TestFixCmdControlsConfigFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantPath string
	}{
		{name: "with verify", args: []string{"report.json", "--verify", "--controls-config", "config.json"}, wantPath: "config.json"},
		{name: "with verify, equals form", args: []string{"report.json", "--verify", "--controls-config=config.json"}, wantPath: "config.json"},
		{name: "not given", args: []string{"report.json", "--verify"}},
		{name: "without verify", args: []string{"report.json", "--controls-config", "config.json"},
			wantErr: "--controls-config only applies to --verify: it is the controls configuration the verification rescan uses"},
		// An unset shell variable gives an empty path. Taken as "not given" the
		// rescan would run under another configuration than the one asked for.
		{name: "empty path", args: []string{"report.json", "--verify", "--controls-config", ""}, wantErr: "--controls-config needs a file path"},
		{name: "empty path with equals", args: []string{"report.json", "--verify", "--controls-config="}, wantErr: "--controls-config needs a file path"},
		{name: "blank path", args: []string{"report.json", "--verify", "--controls-config", "  "}, wantErr: "--controls-config needs a file path"},
		{name: "empty path without verify", args: []string{"report.json", "--controls-config", ""}, wantErr: "--controls-config needs a file path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyKubescape{}
			cmd := GetFixCmd(spy)
			cmd.SetArgs(tt.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()

			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.False(t, spy.fixCalled, "a refused combination must not reach IKubescape.Fix")
				return
			}
			require.NoError(t, err)
			require.True(t, spy.fixCalled)
			assert.Equal(t, tt.wantPath, spy.received.ControlsConfig)
			assert.True(t, spy.received.Verify)
		})
	}
}

func TestFixCmdControlsConfigIsDocumented(t *testing.T) {
	cmd := GetFixCmd(&mocks.MockIKubescape{})

	flag := cmd.PersistentFlags().Lookup("controls-config")
	require.NotNil(t, flag, "the flag must be registered")
	assert.Contains(t, flag.Usage, "--verify")
	assert.Contains(t, flag.Usage, "refuses")
	assert.Contains(t, cmd.Example, "--controls-config")
}

func TestFixCmdPathTrimming(t *testing.T) {
	spy := &spyKubescape{}
	cmd := GetFixCmd(spy)
	cmd.SetArgs([]string{
		"  report.json  ",
		"--output-dir", "  /tmp/fixed  ",
		"--base-path", "  /tmp/base  ",
		"--container-profile", "  /tmp/profile.json  ",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.NoError(t, err)
	require.True(t, spy.fixCalled)
	assert.Equal(t, "report.json", spy.received.ReportFile)
	assert.Equal(t, "/tmp/fixed", spy.received.OutputDir)
	assert.Equal(t, "/tmp/base", spy.received.BasePath)
	assert.Equal(t, "/tmp/profile.json", spy.received.ContainerProfilePath)
}
