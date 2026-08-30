package vap

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func listOutput(t *testing.T, format string, controlsOnly bool) string {
	t.Helper()
	out := &bytes.Buffer{}
	require.NoError(t, runListPolicies(out, format, controlsOnly))
	return out.String()
}

func TestRunListPoliciesJSONMatchesCatalog(t *testing.T) {
	policies, err := cel.ListPolicies()
	require.NoError(t, err)
	require.NotEmpty(t, policies)

	var entries []policyListEntry
	require.NoError(t, json.Unmarshal([]byte(listOutput(t, formatJSON, false)), &entries))
	require.Len(t, entries, len(policies))

	assert.Equal(t, policies[0].PolicyName, entries[0].Policy)
	assert.Equal(t, policies[0].ControlID, entries[0].ControlID)
}

func TestRunListPoliciesControlsOnlyDropsHelpers(t *testing.T) {
	var all, filtered []policyListEntry
	require.NoError(t, json.Unmarshal([]byte(listOutput(t, formatJSON, false)), &all))
	require.NoError(t, json.Unmarshal([]byte(listOutput(t, formatJSON, true)), &filtered))

	require.NotEmpty(t, filtered)
	assert.Less(t, len(filtered), len(all), "the bundle carries helper policies without a control")
	for _, entry := range filtered {
		assert.NotEmpty(t, entry.ControlID)
	}
}

func TestRunListPoliciesYAMLIsParsable(t *testing.T) {
	var entries []policyListEntry
	require.NoError(t, yaml.Unmarshal([]byte(listOutput(t, formatYAML, true)), &entries))
	require.NotEmpty(t, entries)
	assert.NotEmpty(t, entries[0].Policy)
}

func TestRunListPoliciesCSVHasHeaderAndRow(t *testing.T) {
	records, err := csv.NewReader(strings.NewReader(listOutput(t, formatCSV, true))).ReadAll()
	require.NoError(t, err)
	require.Greater(t, len(records), 1)

	assert.Equal(t, []string{"controlID", "policy", "takesParams", "failurePolicy", "resources", "duplicateName", "duplicateControl"}, records[0])
	for _, record := range records[1:] {
		require.Len(t, record, 7)
		assert.NotEmpty(t, record[0])
		assert.NotEmpty(t, record[1])
	}
}

func TestRunListPoliciesPrettyListsKnownControl(t *testing.T) {
	output := listOutput(t, formatPretty, true)
	assert.Contains(t, output, "C-0016")
	assert.Contains(t, output, "Control ID")
	assert.NotContains(t, output, "cluster-policy-deny-attach")
}

func TestRunListPoliciesRejectsUnknownFormat(t *testing.T) {
	err := runListPolicies(&bytes.Buffer{}, "xml", false)
	require.ErrorContains(t, err, "invalid format")
}

func TestListPoliciesCommandIsRegistered(t *testing.T) {
	var names []string
	for _, sub := range GetVapHelperCmd().Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "list-policies")
}

func TestListPoliciesCommandWritesToOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")

	cmd := getListPoliciesCmd()
	stdout := &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SetArgs([]string{"--format", "json", "--controls-only", "--output", path})
	require.NoError(t, cmd.Execute())

	assert.Empty(t, stdout.String(), "output went to the file, not stdout")

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var entries []policyListEntry
	require.NoError(t, json.Unmarshal(raw, &entries))
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		assert.NotEmpty(t, entry.ControlID)
	}
}

func TestListPoliciesCommandWritesToStdoutByDefault(t *testing.T) {
	cmd := getListPoliciesCmd()
	stdout := &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SetArgs([]string{"--controls-only"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, stdout.String(), "C-0016")
}
