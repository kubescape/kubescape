package list

import (
	"context"
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
