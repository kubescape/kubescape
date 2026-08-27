package core

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configInput(path, name, description string) reporthandling.ControlConfigInputs {
	return reporthandling.ControlConfigInputs{Path: path, Name: name, Description: description}
}

func controlWithInputs(id string, inputs ...reporthandling.ControlConfigInputs) reporthandling.Control {
	return reporthandling.Control{
		ControlID: id,
		Rules:     []reporthandling.PolicyRule{{ControlConfigInputs: inputs}},
	}
}

func frameworkWithControls(controls ...reporthandling.Control) []reporthandling.Framework {
	return []reporthandling.Framework{{Controls: controls}}
}

func TestConfigInputKey(t *testing.T) {
	tests := []struct {
		name  string
		input reporthandling.ControlConfigInputs
		want  string
	}{
		{
			name:  "dotted path resolves to its last segment",
			input: configInput("settings.postureControlInputs.imageRepositoryAllowList", "Allowed image repositories", ""),
			want:  "imageRepositoryAllowList",
		},
		{
			name:  "path without a separator is the key itself",
			input: configInput("cpu_limit_max", "cpu_limit_max", ""),
			want:  "cpu_limit_max",
		},
		{
			name:  "name is the fallback when no path is declared",
			input: configInput("", "insecureCapabilities", ""),
			want:  "insecureCapabilities",
		},
		{
			name:  "an input declaring neither is skipped",
			input: configInput("", "", "orphan"),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, configInputKey(tt.input))
		})
	}
}

// TestBuildControlsConfigEntriesJoinsOnTheConfigKey pins the join: controls
// address an input by a dotted path, a controls-config file is keyed by the last
// segment, and the human readable name is only a label. Joining on the label
// instead would leave every value and every control in separate entries.
func TestBuildControlsConfigEntriesJoinsOnTheConfigKey(t *testing.T) {
	values := map[string][]string{
		"imageRepositoryAllowList": {"registry.example.com"},
	}
	frameworks := frameworkWithControls(
		controlWithInputs("C-0078", configInput("settings.postureControlInputs.imageRepositoryAllowList", "Allowed image repositories", "Repositories images may come from.")),
		controlWithInputs("C-0304", configInput("settings.postureControlInputs.imageRepositoryAllowList", "Allowed image repositories", "")),
	)

	entries := buildControlsConfigEntries(values, frameworks)

	require.Len(t, entries, 1)
	assert.Equal(t, "imageRepositoryAllowList", entries[0].Name)
	assert.Equal(t, "Allowed image repositories", entries[0].Title)
	assert.Equal(t, "Repositories images may come from.", entries[0].Description)
	assert.Equal(t, []string{"registry.example.com"}, entries[0].Values)
	assert.Equal(t, []string{"C-0078", "C-0304"}, entries[0].Controls)
}

func TestBuildControlsConfigEntriesListsDeclaredButUnsetInputs(t *testing.T) {
	frameworks := frameworkWithControls(
		controlWithInputs("C-0050", configInput("settings.postureControlInputs.cpu_limit_max", "cpu_limit_max", "")),
	)

	entries := buildControlsConfigEntries(map[string][]string{}, frameworks)

	// An unset input is why a configurable control falls back to its rule
	// default, so it has to appear rather than be filtered out.
	require.Len(t, entries, 1)
	assert.Equal(t, "cpu_limit_max", entries[0].Name)
	assert.Empty(t, entries[0].Values)
	assert.Equal(t, []string{"C-0050"}, entries[0].Controls)
}

func TestBuildControlsConfigEntriesListsValuesNoControlReads(t *testing.T) {
	values := map[string][]string{"retiredSetting": {"true"}}

	entries := buildControlsConfigEntries(values, nil)

	require.Len(t, entries, 1)
	assert.Equal(t, "retiredSetting", entries[0].Name)
	assert.Equal(t, []string{"true"}, entries[0].Values)
	assert.Empty(t, entries[0].Controls)
}

func TestBuildControlsConfigEntriesIsSortedAndDeduplicated(t *testing.T) {
	values := map[string][]string{"zeta": {"1"}, "alpha": {"2"}}
	frameworks := []reporthandling.Framework{
		{Controls: []reporthandling.Control{controlWithInputs("C-0002", configInput("settings.postureControlInputs.middle", "Middle", ""))}},
		{Controls: []reporthandling.Control{controlWithInputs("C-0001", configInput("settings.postureControlInputs.middle", "Middle", ""))}},
	}

	entries := buildControlsConfigEntries(values, frameworks)

	require.Len(t, entries, 3)
	assert.Equal(t, "alpha", entries[0].Name)
	assert.Equal(t, "middle", entries[1].Name)
	assert.Equal(t, "zeta", entries[2].Name)

	// The same input declared by two frameworks yields one entry naming both.
	assert.Equal(t, []string{"C-0001", "C-0002"}, entries[1].Controls)
}

func TestBuildControlsConfigEntriesDoesNotAliasTheConfigValues(t *testing.T) {
	values := map[string][]string{"key": {"original"}}

	entries := buildControlsConfigEntries(values, nil)
	require.Len(t, entries, 1)
	entries[0].Values[0] = "mutated"

	assert.Equal(t, []string{"original"}, values["key"], "the caller's configuration must not be modified")
}

func TestBuildControlsConfigEntriesSkipsInputsWithoutAKey(t *testing.T) {
	frameworks := frameworkWithControls(controlWithInputs("C-0001", configInput("", "", "")))

	assert.Empty(t, buildControlsConfigEntries(map[string][]string{}, frameworks))
}

func TestListSupportActionsIncludesControlsConfig(t *testing.T) {
	assert.Contains(t, ListSupportActions(), "controls-config")
}

func TestPrintListResultRejectsAnUnknownControlsConfigFormat(t *testing.T) {
	result := &metav1.ListResult{ControlsConfig: []metav1.ControlConfigEntry{{Name: "key"}}}

	err := PrintListResult(t.Context(), result, "controls-config", "xml")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pretty-print")
}

type stubConfigGetter struct {
	values      map[string][]string
	err         error
	clusterName string
}

func (s *stubConfigGetter) GetControlsInputs(_ context.Context, clusterName string) (map[string][]string, error) {
	s.clusterName = clusterName
	return s.values, s.err
}

type stubPolicyGetter struct {
	getter.IPolicyGetter
	frameworks []reporthandling.Framework
	err        error
}

func (s *stubPolicyGetter) GetFrameworks() ([]reporthandling.Framework, error) {
	return s.frameworks, s.err
}

func TestControlsConfigEntriesJoinsBothLookups(t *testing.T) {
	config := &stubConfigGetter{values: map[string][]string{"insecureCapabilities": {"SETUID"}}}
	policies := &stubPolicyGetter{frameworks: frameworkWithControls(
		controlWithInputs("C-0046", configInput("settings.postureControlInputs.insecureCapabilities", "Insecure capabilities", "")),
	)}

	entries, err := controlsConfigEntries(t.Context(), config, policies, "my-cluster")

	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, []string{"SETUID"}, entries[0].Values)
	assert.Equal(t, []string{"C-0046"}, entries[0].Controls)
	assert.Equal(t, "my-cluster", config.clusterName, "the cluster name must reach the configuration source")
}

func TestControlsConfigEntriesSurfacesAConfigurationError(t *testing.T) {
	config := &stubConfigGetter{err: errors.New("controls-config unreachable")}
	policies := &stubPolicyGetter{frameworks: frameworkWithControls(controlWithInputs("C-0046"))}

	_, err := controlsConfigEntries(t.Context(), config, policies, "")

	// Reporting an empty configuration would read as "nothing is configured",
	// which is not the same as "the configuration could not be read".
	require.Error(t, err)
	assert.Contains(t, err.Error(), "controls-config unreachable")
}

func TestControlsConfigEntriesSurfacesAPolicyError(t *testing.T) {
	config := &stubConfigGetter{values: map[string][]string{"key": {"value"}}}
	policies := &stubPolicyGetter{err: errors.New("frameworks unavailable")}

	_, err := controlsConfigEntries(t.Context(), config, policies, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "frameworks unavailable")
}
