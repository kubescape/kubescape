package list

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingListKubescape struct {
	meta.IKubescape
	received *metav1.ListPolicies
}

func (r *recordingListKubescape) Context() context.Context {
	return context.Background()
}

func (r *recordingListKubescape) List(listPolicies *metav1.ListPolicies) (*metav1.ListResult, error) {
	copy := *listPolicies
	r.received = &copy
	return &metav1.ListResult{}, nil
}

func TestGetListCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetListCmd function
	listCmd := GetListCmd(mockKubescape)

	assert.Equal(t, "list <policy> [flags]", listCmd.Use)
	supported := strings.Join(core.ListSupportActions(), ",")

	err := listCmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "policy type required, supported: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"not-frameworks"})
	expectedErrorMessage = "invalid parameter 'not-frameworks'. Supported parameters: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"frameworks"})
	assert.Nil(t, err)

	err = listCmd.Args(&cobra.Command{Use: "list"}, []string{"frameworks", "unexpected"})
	assert.EqualError(t, err, `unknown command "unexpected" for "list"`)

	err = listCmd.RunE(&cobra.Command{}, []string{"some-value"})
	assert.ErrorContains(t, err, "invalid target")
}

func TestGetListCmd_ControlFilterFlags(t *testing.T) {
	recorder := &recordingListKubescape{}
	listCmd := GetListCmd(recorder)
	listCmd.SetArgs([]string{"controls", "--framework", "NSA", "--search", "container", "--format", "json"})

	require.NoError(t, listCmd.Execute())
	require.NotNil(t, recorder.received)
	assert.Equal(t, "controls", recorder.received.Target)
	assert.Equal(t, "json", recorder.received.Format)
	assert.Equal(t, "NSA", recorder.received.ControlFilters.Framework)
	assert.Equal(t, "container", recorder.received.ControlFilters.Search)
}

func TestGetListCmd_ControlFilterFlagsRejectNonControlsTarget(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "framework flag only",
			args:    []string{"frameworks", "--framework", "NSA"},
			wantErr: "--framework can only be used with 'list controls'",
		},
		{
			name:    "search flag only",
			args:    []string{"frameworks", "--search", "container"},
			wantErr: "--search can only be used with 'list controls'",
		},
		{
			name:    "both framework and search flags",
			args:    []string{"frameworks", "--framework", "NSA", "--search", "container"},
			wantErr: "--framework and --search can only be used with 'list controls'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listCmd := GetListCmd(&recordingListKubescape{})
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestGetListCmd_ControlFilterFlagsAllowsNonControlsWhenUnsetOrWhitespace(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no filter flags passed",
			args: []string{"frameworks"},
		},
		{
			name: "whitespace framework and search flags passed",
			args: []string{"frameworks", "--framework", "   ", "--search", "\t"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := &recordingListKubescape{}
			listCmd := GetListCmd(recorder)
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			require.NoError(t, err)
			require.NotNil(t, recorder.received)
			assert.Equal(t, "frameworks", recorder.received.Target)
		})
	}
}

func TestGetListCmd_ControlFilterFlagMetadata(t *testing.T) {
	listCmd := GetListCmd(&mocks.MockIKubescape{})

	frameworkFlag := listCmd.PersistentFlags().Lookup("framework")
	require.NotNil(t, frameworkFlag)
	assert.Equal(t, "", frameworkFlag.DefValue)

	searchFlag := listCmd.PersistentFlags().Lookup("search")
	require.NotNil(t, searchFlag)
	assert.Equal(t, "", searchFlag.DefValue)
}

func TestGetListCmd_ControlsConfigFlag(t *testing.T) {
	recorder := &recordingListKubescape{}
	listCmd := GetListCmd(recorder)
	listCmd.SetArgs([]string{"controls-config", "--controls-config", "./controls-inputs.json", "--format", "json"})

	require.NoError(t, listCmd.Execute())
	require.NotNil(t, recorder.received)
	assert.Equal(t, "controls-config", recorder.received.Target)
	assert.Equal(t, "json", recorder.received.Format)
	assert.Equal(t, "./controls-inputs.json", recorder.received.ControlsInputs)
}

func TestGetListCmd_ControlsConfigFlagRejectNonControlsConfigTarget(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "controls-config with controls target",
			args:    []string{"controls", "--controls-config", "./controls-inputs.json"},
			wantErr: "--controls-config can only be used with 'list controls-config'",
		},
		{
			name:    "controls-config with frameworks target",
			args:    []string{"frameworks", "--controls-config", "./controls-inputs.json"},
			wantErr: "--controls-config can only be used with 'list controls-config'",
		},
		{
			name:    "controls-config with exceptions target",
			args:    []string{"exceptions", "--controls-config", "./controls-inputs.json"},
			wantErr: "--controls-config can only be used with 'list controls-config'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listCmd := GetListCmd(&recordingListKubescape{})
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestGetListCmd_ControlsConfigFlagAllowsNonControlsConfigWhenUnsetOrWhitespace(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		target string
	}{
		{
			name:   "no controls-config flag passed for frameworks",
			args:   []string{"frameworks"},
			target: "frameworks",
		},
		{
			name:   "whitespace controls-config flag passed for frameworks",
			args:   []string{"frameworks", "--controls-config", "   "},
			target: "frameworks",
		},
		{
			name:   "whitespace controls-config flag passed for controls",
			args:   []string{"controls", "--controls-config", " \t "},
			target: "controls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := &recordingListKubescape{}
			listCmd := GetListCmd(recorder)
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			require.NoError(t, err)
			require.NotNil(t, recorder.received)
			assert.Equal(t, tt.target, recorder.received.Target)
		})
	}
}

func TestGetListCmd_ControlsConfigFlagMetadata(t *testing.T) {
	listCmd := GetListCmd(&mocks.MockIKubescape{})

	controlsConfigFlag := listCmd.PersistentFlags().Lookup("controls-config")
	require.NotNil(t, controlsConfigFlag)
	assert.Equal(t, "", controlsConfigFlag.DefValue)
	assert.Contains(t, controlsConfigFlag.Usage, "Only applies to 'controls-config'")
}

func TestGetListCmd_FormatValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		expectedErr string
		wantFormat  string
	}{
		{
			name:        "invalid format rejected upfront",
			args:        []string{"controls", "--format", "invalid"},
			wantErr:     true,
			expectedErr: `invalid format "invalid", supported formats: 'pretty-print'/'json'/'yaml'/'csv'`,
		},
		{
			name:        "unsupported sarif format rejected upfront",
			args:        []string{"controls", "--format", "sarif"},
			wantErr:     true,
			expectedErr: `invalid format "sarif", supported formats: 'pretty-print'/'json'/'yaml'/'csv'`,
		},
		{
			name:        "empty format rejected",
			args:        []string{"controls", "--format", ""},
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats: 'pretty-print'/'json'/'yaml'/'csv'",
		},
		{
			name:        "whitespace-only format rejected",
			args:        []string{"controls", "--format", "   "},
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats: 'pretty-print'/'json'/'yaml'/'csv'",
		},
		{
			name:       "valid json format passes",
			args:       []string{"controls", "--format", "json"},
			wantErr:    false,
			wantFormat: "json",
		},
		{
			name:       "valid uppercase and untrimmed format normalizes",
			args:       []string{"controls", "--format", " YAML "},
			wantErr:    false,
			wantFormat: "yaml",
		},
		{
			name:       "valid pretty-print format passes",
			args:       []string{"frameworks", "--format", "pretty-print"},
			wantErr:    false,
			wantFormat: "pretty-print",
		},
		{
			name:       "valid csv format passes",
			args:       []string{"controls-config", "--format", "csv"},
			wantErr:    false,
			wantFormat: "csv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := &recordingListKubescape{}
			listCmd := GetListCmd(recorder)
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.expectedErr, err.Error())
				assert.Nil(t, recorder.received, "ks.List should not be called when format validation fails")
			} else {
				require.NoError(t, err)
				require.NotNil(t, recorder.received)
				assert.Equal(t, tt.wantFormat, recorder.received.Format)
			}
		})
	}
}

func TestGetListCmd_RejectsUnexpectedArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "unexpected arg on controls",
			args:    []string{"controls", "extra"},
			wantErr: `unknown command "extra" for "list"`,
		},
		{
			name:    "unexpected arg on frameworks",
			args:    []string{"frameworks", "nsa"},
			wantErr: `unknown command "nsa" for "list"`,
		},
		{
			name:    "unexpected arg on controls-config",
			args:    []string{"controls-config", "unexpected"},
			wantErr: `unknown command "unexpected" for "list"`,
		},
		{
			name:    "unexpected arg on exceptions",
			args:    []string{"exceptions", "unexpected"},
			wantErr: `unknown command "unexpected" for "list"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listCmd := GetListCmd(&recordingListKubescape{})
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetArgs(tt.args)

			err := listCmd.Execute()
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

type stubListKubescapeWithData struct {
	meta.IKubescape
	result *metav1.ListResult
}

func (s *stubListKubescapeWithData) Context() context.Context {
	return context.Background()
}

func (s *stubListKubescapeWithData) List(listPolicies *metav1.ListPolicies) (*metav1.ListResult, error) {
	return s.result, nil
}

type failingListWriter struct {
	err error
}

func (w failingListWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}

func TestGetListCmd_HonorsCommandOutputWriter(t *testing.T) {
	stubData := &metav1.ListResult{
		Names: []string{"nsa", "mitre"},
		Controls: []metav1.ControlListEntry{
			{ID: "C-0001", Name: "Forbidden Registries", Frameworks: []string{"NSA"}},
		},
		ControlsConfig: []metav1.ControlConfigEntry{
			{Name: "imageRepositoryAllowList", Title: "Allowed Images", Values: []string{"quay.io"}, Controls: []string{"C-0001"}, Description: "Desc"},
		},
	}

	formats := []string{"pretty-print", "json", "yaml", "csv"}
	targets := []string{"frameworks", "controls", "controls-config"}

	for _, target := range targets {
		for _, format := range formats {
			t.Run(target+"_"+format, func(t *testing.T) {
				ks := &stubListKubescapeWithData{result: stubData}
				cmd := GetListCmd(ks)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true

				var buf bytes.Buffer
				cmd.SetOut(&buf)
				cmd.SetArgs([]string{target, "--format", format})

				err := cmd.Execute()
				require.NoError(t, err)
				assert.NotEmpty(t, buf.String(), "output should be written to configured command writer")

				switch target {
				case "frameworks":
					assert.Contains(t, buf.String(), "nsa")
				case "controls":
					assert.Contains(t, buf.String(), "C-0001")
				case "controls-config":
					assert.Contains(t, buf.String(), "imageRepositoryAllowList")
				}
			})
		}
	}
}

func TestGetListCmd_PropagatesWriterError(t *testing.T) {
	stubData := &metav1.ListResult{
		Names: []string{"nsa"},
		Controls: []metav1.ControlListEntry{
			{ID: "C-0001", Name: "Forbidden Registries", Frameworks: []string{"NSA"}},
		},
		ControlsConfig: []metav1.ControlConfigEntry{
			{Name: "imageRepositoryAllowList", Title: "Allowed Images", Values: []string{"quay.io"}, Controls: []string{"C-0001"}, Description: "Desc"},
		},
	}

	writeErr := errors.New("simulated output write failure")

	formats := []string{"pretty-print", "json", "yaml", "csv"}
	targets := []string{"frameworks", "controls", "controls-config"}

	for _, target := range targets {
		for _, format := range formats {
			t.Run(target+"_"+format, func(t *testing.T) {
				ks := &stubListKubescapeWithData{result: stubData}
				cmd := GetListCmd(ks)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				cmd.SetOut(failingListWriter{err: writeErr})
				cmd.SetArgs([]string{target, "--format", format})

				err := cmd.Execute()
				require.Error(t, err)
				assert.ErrorIs(t, err, writeErr)
			})
		}
	}
}

func TestNormalizeListTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"controls", "controls"},
		{"control", "controls"},
		{"Control", "controls"},
		{" CONTROLS ", "controls"},
		{"frameworks", "frameworks"},
		{"framework", "frameworks"},
		{"FRAMEWORK", "frameworks"},
		{"  frameworks  ", "frameworks"},
		{"controls-config", "controls-config"},
		{"controls-inputs", "controls-config"},
		{"controls-input", "controls-config"},
		{"control-inputs", "controls-config"},
		{"control-input", "controls-config"},
		{"control-config", "controls-config"},
		{"CONTROLS-INPUTS", "controls-config"},
		{"exceptions", "exceptions"},
		{"exception", "exceptions"},
		{"EXCEPTION", "exceptions"},
		{"other", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeListTarget(tt.input))
		})
	}
}

func TestGetListCmd_NormalizedTargetExecution(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		wantTarget string
	}{
		{name: "singular framework", arg: "framework", wantTarget: "frameworks"},
		{name: "uppercase frameworks", arg: "FRAMEWORKS", wantTarget: "frameworks"},
		{name: "whitespace frameworks", arg: "  frameworks  ", wantTarget: "frameworks"},
		{name: "singular control", arg: "control", wantTarget: "controls"},
		{name: "uppercase controls", arg: "CONTROLS", wantTarget: "controls"},
		{name: "controls-inputs alias", arg: "controls-inputs", wantTarget: "controls-config"},
		{name: "control-inputs alias", arg: "control-inputs", wantTarget: "controls-config"},
		{name: "singular exception", arg: "exception", wantTarget: "exceptions"},
		{name: "uppercase exceptions", arg: "EXCEPTIONS", wantTarget: "exceptions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := &recordingListKubescape{}
			listCmd := GetListCmd(recorder)
			listCmd.SilenceUsage = true
			listCmd.SilenceErrors = true
			listCmd.SetOut(io.Discard)
			listCmd.SetErr(io.Discard)
			listCmd.SetArgs([]string{tt.arg})

			err := listCmd.Execute()
			require.NoError(t, err)
			require.NotNil(t, recorder.received)
			assert.Equal(t, tt.wantTarget, recorder.received.Target)
		})
	}
}

func TestGetListCmd_ControlFilterFlagsWithSingularTarget(t *testing.T) {
	recorder := &recordingListKubescape{}
	listCmd := GetListCmd(recorder)
	listCmd.SilenceUsage = true
	listCmd.SilenceErrors = true
	listCmd.SetOut(io.Discard)
	listCmd.SetErr(io.Discard)
	listCmd.SetArgs([]string{"control", "--framework", "NSA", "--search", "container"})

	require.NoError(t, listCmd.Execute())
	require.NotNil(t, recorder.received)
	assert.Equal(t, "controls", recorder.received.Target)
	assert.Equal(t, "NSA", recorder.received.ControlFilters.Framework)
	assert.Equal(t, "container", recorder.received.ControlFilters.Search)
}
