package core

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
)

// Function receives a non-empty list of policies
func TestNonEmptyListOfPolicies(t *testing.T) {
	policies := []string{"policy1", "policy2", "policy3"}

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonListFormat(context.Background(), "", policies)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	want := `[
  "policy1",
  "policy2",
  "policy3"
]
`
	assert.Equal(t, want, string(got))
}

// Function returns a valid JSON string
func TestValidJsonString(t *testing.T) {
	policies := []string{"policy1", "policy2", "policy3"}

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonListFormat(context.Background(), "", policies)

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	var result []string
	err := json.Unmarshal(out, &result)
	assert.NoError(t, err)
}

// Function receives an empty list of policies
func TestEmptyListOfPolicies(t *testing.T) {
	policies := []string{}

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonListFormat(context.Background(), "", policies)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	want := "[]\n"

	assert.Equal(t, want, string(got))
}

// Function receives a nil list of policies
func TestNilListOfPolicies(t *testing.T) {
	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonListFormat(context.Background(), "", nil)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	want := "null\n"

	assert.Equal(t, want, string(got))
}

// Returns a 2D slice with one row for each policy in the input slice.
func TestGeneratePolicyRows_NonEmptyPolicyList(t *testing.T) {
	// Arrange
	policies := []string{"policy1", "policy2", "policy3"}

	// Act
	result := generatePolicyRows(policies)

	// Assert
	assert.Equal(t, []table.Row{{"policy1"}, {"policy2"}, {"policy3"}}, result)
}

// Returns an empty 2D slice for an empty list of policies.
func TestGeneratePolicyRows_EmptyPolicyList(t *testing.T) {
	// Arrange
	policies := []string{}

	// Act
	got := generatePolicyRows(policies)

	// Assert
	assert.Empty(t, got)
}

// The function returns a list of rows, each containing a formatted string with control ID, control name, docs, and frameworks.
func TestShortFormatControlRows_ReturnsListOfRowsWithFormattedString(t *testing.T) {
	controlRows := []table.Row{
		{"ID1", "Control 1", "Docs 1", "Framework 1"},
		{"ID2", "Control 2", "Docs 2", "Framework 2"},
	}

	want := []table.Row{
		{"Control ID   : ID1\nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
		{"Control ID   : ID2\nControl Name : Control 2\nDocs         : Docs 2\nFrameworks   : Framework 2"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

// The function formats the control rows correctly, replacing newlines in the frameworks column with spaces.
func TestShortFormatControlRows_FormatsControlRowsCorrectly(t *testing.T) {
	controlRows := []table.Row{
		{"ID1", "Control 1", "Docs 1", "Framework\n1"},
		{"ID2", "Control 2", "Docs 2", "Framework\n2"},
	}

	want := []table.Row{
		{"Control ID   : ID1\nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
		{"Control ID   : ID2\nControl Name : Control 2\nDocs         : Docs 2\nFrameworks   : Framework 2"},
	}

	result := shortFormatControlRows(controlRows)

	assert.Equal(t, want, result)
}

// The function handles a control row with an empty control ID.
func TestShortFormatControlRows_HandlesControlRowWithEmptyControlID(t *testing.T) {
	controlRows := []table.Row{
		{"", "Control 1", "Docs 1", "Framework 1"},
	}

	want := []table.Row{
		{"Control ID   : \nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

// The function handles a control row with an empty control name.
func TestShortFormatControlRows_HandlesControlRowWithEmptyControlName(t *testing.T) {
	controlRows := []table.Row{
		{"ID1", "", "Docs 1", "Framework 1"},
	}

	want := []table.Row{
		{"Control ID   : ID1\nControl Name : \nDocs         : Docs 1\nFrameworks   : Framework 1"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

func TestParseControlEntry(t *testing.T) {
	tests := []struct {
		name string
		pipe string
		want metav1.ControlListEntry
	}{
		{
			name: "full entry with multiple frameworks",
			pipe: "C-0001|Forbidden Container Registries|NSA, AllControls, MITRE",
			want: metav1.ControlListEntry{
				ID:         "C-0001",
				Name:       "Forbidden Container Registries",
				Frameworks: []string{"NSA", "AllControls", "MITRE"},
			},
		},
		{
			name: "entry with single framework",
			pipe: "C-0001|Name|NSA",
			want: metav1.ControlListEntry{
				ID:         "C-0001",
				Name:       "Name",
				Frameworks: []string{"NSA"},
			},
		},
		{
			name: "entry with empty frameworks field",
			pipe: "C-0001|Name|",
			want: metav1.ControlListEntry{
				ID:         "C-0001",
				Name:       "Name",
				Frameworks: []string{},
			},
		},
		{
			name: "entry without frameworks field",
			pipe: "C-0001|Name",
			want: metav1.ControlListEntry{
				ID:         "C-0001",
				Name:       "Name",
				Frameworks: []string{},
			},
		},
		{
			name: "entry with only ID",
			pipe: "C-0001",
			want: metav1.ControlListEntry{
				ID:         "C-0001",
				Frameworks: []string{},
			},
		},
		{
			name: "empty string",
			pipe: "",
			want: metav1.ControlListEntry{
				Frameworks: []string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseControlEntry(tt.pipe)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Generates rows for each entry with ID, name, documentation link, and frameworks.
func TestGenerateControlRowsWithAllFields(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "1", Name: "Control 1", Frameworks: []string{"NSA", "MITRE"}},
		{ID: "2", Name: "Control 2", Frameworks: []string{"AllControls"}},
		{ID: "3", Name: "Control 3", Frameworks: []string{}},
	}

	want := []table.Row{
		{"1", "Control 1", "https://hub.armosec.io/docs/1", "NSA\nMITRE"},
		{"2", "Control 2", "https://hub.armosec.io/docs/2", "AllControls"},
		{"3", "Control 3", "https://hub.armosec.io/docs/3", ""},
	}

	got := generateControlRows(entries)

	assert.Equal(t, want, got)
}

// Handles entries with missing or empty fields.
func TestGenerateControlRowsHandlesMissingFields(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "", Name: "", Frameworks: []string{}},
		{ID: "1", Name: "", Frameworks: []string{}},
		{ID: "2", Name: "Control 2", Frameworks: []string{"NSA", "MITRE"}},
	}

	want := []table.Row{
		{"", "", "https://hub.armosec.io/docs/", ""},
		{"1", "", "https://hub.armosec.io/docs/1", ""},
		{"2", "Control 2", "https://hub.armosec.io/docs/2", "NSA\nMITRE"},
	}

	got := generateControlRows(entries)

	assert.Equal(t, want, got)
}

// jsonControlsFormat emits a JSON array of objects, not pipe-delimited strings.
func TestJsonControlsFormat(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Forbidden Container Registries", Frameworks: []string{}},
		{ID: "C-0002", Name: "Prevent containers from allowing command execution", Frameworks: []string{"NSA", "AllControls", "MITRE"}},
	}

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonControlsFormat(entries)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	// Verify it is valid JSON that unmarshals into typed objects (not strings).
	var result []metav1.ControlListEntry
	assert.NoError(t, json.Unmarshal(got, &result))
	assert.Len(t, result, 2)

	assert.Equal(t, "C-0001", result[0].ID)
	assert.Equal(t, "Forbidden Container Registries", result[0].Name)
	assert.Equal(t, []string{}, result[0].Frameworks)

	assert.Equal(t, "C-0002", result[1].ID)
	assert.Equal(t, []string{"NSA", "AllControls", "MITRE"}, result[1].Frameworks)

	// Verify the raw output contains object keys, not pipe-delimited strings.
	assert.Contains(t, string(got), `"id"`)
	assert.Contains(t, string(got), `"name"`)
	assert.Contains(t, string(got), `"frameworks"`)
	assert.NotContains(t, string(got), "|")
}

// The function generates a table with the correct headers and rows based on the input entries.
func TestGenerateTableWithCorrectHeadersAndRows(t *testing.T) {
	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "1", Name: "Control 1", Frameworks: []string{"NSA"}},
		{ID: "2", Name: "Control 2", Frameworks: []string{"MITRE"}},
		{ID: "3", Name: "Control 3", Frameworks: []string{"NSA", "MITRE"}},
	}

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	prettyPrintControls(ctx, entries)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	want := `╭────────────┬──────────────┬───────────────────────────────┬────────────╮
│ Control ID │ Control name │ Docs                          │ Frameworks │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          1 │ Control 1    │ https://hub.armosec.io/docs/1 │ NSA        │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          2 │ Control 2    │ https://hub.armosec.io/docs/2 │ MITRE      │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          3 │ Control 3    │ https://hub.armosec.io/docs/3 │ NSA        │
│            │              │                               │ MITRE      │
╰────────────┴──────────────┴───────────────────────────────┴────────────╯
`

	assert.Equal(t, want, string(got))
}

func TestGenerateTableWithPartialEntriesAndPrettyPrintHeadersAndRows(t *testing.T) {
	ctx := context.Background()
	entries := []metav1.ControlListEntry{
		{ID: "", Name: "", Frameworks: []string{}},
		{ID: "1", Name: "", Frameworks: []string{}},
		{ID: "2", Name: "Control 2", Frameworks: []string{"NSA"}},
		{ID: "3", Name: "Control 3", Frameworks: []string{"MITRE"}},
		{ID: "4", Name: "", Frameworks: []string{"NSA"}},
		{ID: "", Name: "", Frameworks: []string{}},
		{ID: "5", Name: "Control 5", Frameworks: []string{}},
	}

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	prettyPrintControls(ctx, entries)

	w.Close()
	got, _ := io.ReadAll(r)

	os.Stdout = rescueStdout

	want := `╭────────────┬──────────────┬───────────────────────────────┬────────────╮
│ Control ID │ Control name │ Docs                          │ Frameworks │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│            │              │ https://hub.armosec.io/docs/  │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          1 │              │ https://hub.armosec.io/docs/1 │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          2 │ Control 2    │ https://hub.armosec.io/docs/2 │ NSA        │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          3 │ Control 3    │ https://hub.armosec.io/docs/3 │ MITRE      │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          4 │              │ https://hub.armosec.io/docs/4 │ NSA        │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│            │              │ https://hub.armosec.io/docs/  │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          5 │ Control 5    │ https://hub.armosec.io/docs/5 │            │
╰────────────┴──────────────┴───────────────────────────────┴────────────╯
`

	assert.Equal(t, want, string(got))
}

// Returns a non-empty list of supported actions when 'ListSupportActions' is called.
func TestListSupportActionsNotEmpty(t *testing.T) {
	actions := ListSupportActions()
	assert.NotEmpty(t, actions)
}

func TestListSupportActionsReturnsSupportedActions(t *testing.T) {
	got := ListSupportActions()
	want := []string{"controls", "exceptions", "frameworks"}
	sort.Strings(got)

	assert.Equal(t, want, got)
}

func TestListFrameworks(t *testing.T) {
	ctx := context.Background()
	listPolicies := &metav1.ListPolicies{
		Target:    "all",
		Format:    "json",
		AccountID: "1234567890",
		AccessKey: "myaccesskey",
	}

	frameworks, err := listFrameworks(ctx, listPolicies)

	assert.NotEmpty(t, frameworks)
	assert.Nil(t, err)
}

func TestListControls(t *testing.T) {
	ctx := context.Background()
	listPolicies := &metav1.ListPolicies{
		Target:    "all",
		Format:    "json",
		AccountID: "1234567890",
		AccessKey: "myaccesskey",
	}

	controls, err := listControls(ctx, listPolicies)

	assert.NotNil(t, controls)
	assert.Nil(t, err)
}

func TestListExceptions(t *testing.T) {
	ctx := context.Background()
	listPolicies := &metav1.ListPolicies{
		Target:    "all",
		Format:    "json",
		AccountID: "1234567890",
		AccessKey: "myaccesskey",
	}

	controls, err := listExceptions(ctx, listPolicies)

	assert.Nil(t, controls)
	assert.NotNil(t, err)
}

func TestNaturalSortPolicies(t *testing.T) {
	type args struct {
		policies []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty",
			args: args{
				policies: []string{},
			},
			want: []string{},
		},
		{
			name: "one element",
			args: args{
				policies: []string{"policy-1"},
			},
			want: []string{"policy-1"},
		},
		{
			name: "Natural sort",
			args: args{
				policies: []string{"policy-1", "policy-11", "policy-12", "policy-2"},
			},
			want: []string{"policy-1", "policy-2", "policy-11", "policy-12"},
		},
		{
			name: "Natural sort 2",
			args: args{
				policies: []string{"exclude-aks-kube-system-daemonsets-10", "exclude-aks-kube-system-daemonsets-4", "exclude-aks-kube-system-daemonsets-1",
					"exclude-gke-kube-public-resources", "exclude-kubescape-otel",
				},
			},
			want: []string{"exclude-aks-kube-system-daemonsets-1", "exclude-aks-kube-system-daemonsets-4", "exclude-aks-kube-system-daemonsets-10", "exclude-gke-kube-public-resources", "exclude-kubescape-otel"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := naturalSortPolicies(tt.args.policies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sortPolicies() = %v, want %v", got, tt.want)
			}
		})
	}
}
