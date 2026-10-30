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
	require.ErrorContains(t, err, `invalid format "xml", supported formats: 'pretty-print'/'json'/'yaml'/'csv'`)
}

func TestRunListPolicies_FormatValidation(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "uppercase format is normalized",
			format:  "JSON",
			wantErr: false,
		},
		{
			name:    "padded format is normalized",
			format:  "  yaml  ",
			wantErr: false,
		},
		{
			name:    "mixed-case pretty-print is normalized",
			format:  " Pretty-Print ",
			wantErr: false,
		},
		{
			name:    "uppercase csv is normalized",
			format:  "CSV",
			wantErr: false,
		},
		{
			name:        "empty format is rejected",
			format:      "",
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats:",
		},
		{
			name:        "whitespace-only format is rejected",
			format:      "   ",
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats:",
		},
		{
			name:        "unknown format is rejected",
			format:      "xml",
			wantErr:     true,
			expectedErr: `invalid format "xml", supported formats: 'pretty-print'/'json'/'yaml'/'csv'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := runListPolicies(buf, tt.format, true)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, buf.String())
			}
		})
	}
}

func TestListPoliciesCommand_FormatValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "uppercase format flag succeeds",
			args:    []string{"--format", "JSON", "--controls-only"},
			wantErr: false,
		},
		{
			name:    "padded format flag succeeds",
			args:    []string{"--format", "  yaml  ", "--controls-only"},
			wantErr: false,
		},
		{
			name:        "empty format flag is rejected upfront",
			args:        []string{"--format", "", "--controls-only"},
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats:",
		},
		{
			name:        "whitespace-only format flag is rejected upfront",
			args:        []string{"--format", "   ", "--controls-only"},
			wantErr:     true,
			expectedErr: "format cannot be empty, supported formats:",
		},
		{
			name:        "unknown format flag is rejected upfront",
			args:        []string{"--format", "invalid", "--controls-only"},
			wantErr:     true,
			expectedErr: `invalid format "invalid", supported formats: 'pretty-print'/'json'/'yaml'/'csv'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getListPoliciesCmd()
			stdout := &bytes.Buffer{}
			cmd.SetOut(stdout)
			cmd.SetErr(stdout)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, stdout.String())
			}
		})
	}
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

// TestCsvSafeCell_VAP verifies that cells starting with spreadsheet formula
// prefix characters (=, +, -, @, \t, \r, \n) are prepended with a single quote.
func TestCsvSafeCell_VAP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty stays empty", in: "", want: ""},
		{name: "plain text is unchanged", in: "demo", want: "demo"},
		{name: "equals is neutralized", in: "=1+1", want: "'=1+1"},
		{name: "plus is neutralized", in: "+1", want: "'+1"},
		{name: "minus is neutralized", in: "-1", want: "'-1"},
		{name: "at sign is neutralized", in: "@SUM(A1)", want: "'@SUM(A1)"},
		{name: "tab is neutralized", in: "\tcmd", want: "'\tcmd"},
		{name: "carriage return is neutralized", in: "\rcmd", want: "'\rcmd"},
		{name: "line feed is neutralized", in: "\n=1+1", want: "'\n=1+1"},
		{name: "dde payload is neutralized", in: "=cmd|' /C calc'!A0", want: "'=cmd|' /C calc'!A0"},
		{name: "leading pipe is not a formula prefix", in: "|table", want: "|table"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, csvSafeCell(tc.in))
		})
	}
}

func TestCsvPolicies_NeutralizesFormulaInjection(t *testing.T) {
	entries := []policyListEntry{
		{
			ControlID:        "+C-0001",
			Policy:           "=cmd|' /C calc'!A0",
			TakesParams:      true,
			FailurePolicy:    "@Fail",
			Resources:        []string{"-pods", "=deployments"},
			DuplicateName:    false,
			DuplicateControl: false,
		},
	}

	buf := &bytes.Buffer{}
	require.NoError(t, csvPolicies(buf, entries))

	records, err := csv.NewReader(buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"controlID", "policy", "takesParams", "failurePolicy", "resources", "duplicateName", "duplicateControl"}, records[0])
	assert.Equal(t, []string{
		"'+C-0001",
		"'=cmd|' /C calc'!A0",
		"true",
		"'@Fail",
		"'-pods;=deployments",
		"false",
		"false",
	}, records[1])
}
