package core

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sort"
	"testing"

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

	// got := buf.String()
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
	assert.Equal(t, [][]string{{"policy1"}, {"policy2"}, {"policy3"}}, result)
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
	controlRows := [][]string{
		{"ID1", "Control 1", "Docs 1", "Framework 1"},
		{"ID2", "Control 2", "Docs 2", "Framework 2"},
	}

	want := [][]string{
		{"Control ID   : ID1\nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
		{"Control ID   : ID2\nControl Name : Control 2\nDocs         : Docs 2\nFrameworks   : Framework 2"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

// The function formats the control rows correctly, replacing newlines in the frameworks column with line breaks.
func TestShortFormatControlRows_FormatsControlRowsCorrectly(t *testing.T) {
	controlRows := [][]string{
		{"ID1", "Control 1", "Docs 1", "Framework\n1"},
		{"ID2", "Control 2", "Docs 2", "Framework\n2"},
	}

	want := [][]string{
		{"Control ID   : ID1\nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
		{"Control ID   : ID2\nControl Name : Control 2\nDocs         : Docs 2\nFrameworks   : Framework 2"},
	}

	result := shortFormatControlRows(controlRows)

	assert.Equal(t, want, result)
}

// The function handles a control row with an empty control ID.
func TestShortFormatControlRows_HandlesControlRowWithEmptyControlID(t *testing.T) {
	controlRows := [][]string{
		{"", "Control 1", "Docs 1", "Framework 1"},
	}

	want := [][]string{
		{"Control ID   : \nControl Name : Control 1\nDocs         : Docs 1\nFrameworks   : Framework 1"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

// The function handles a control row with an empty control name.
func TestShortFormatControlRows_HandlesControlRowWithEmptyControlName(t *testing.T) {
	controlRows := [][]string{
		{"ID1", "", "Docs 1", "Framework 1"},
	}

	want := [][]string{
		{"Control ID   : ID1\nControl Name : \nDocs         : Docs 1\nFrameworks   : Framework 1"},
	}

	got := shortFormatControlRows(controlRows)

	assert.Equal(t, want, got)
}

// Generates rows for each policy with ID, control, documentation, and framework
func TestGenerateControlRowsWithAllFields(t *testing.T) {
	policies := []string{
		"1|Control 1|Framework 1",
		"2|Control 2|Framework 2",
		"3|Control 3|Framework 3",
	}

	want := [][]string{
		{"1", "Control 1", "https://hub.armosec.io/docs/1", "Framework\n1"},
		{"2", "Control 2", "https://hub.armosec.io/docs/2", "Framework\n2"},
		{"3", "Control 3", "https://hub.armosec.io/docs/3", "Framework\n3"},
	}

	got := generateControlRows(policies)

	assert.Equal(t, want, got)
}

// Handles policies with no '|' characters in the string
func TestGenerateControlRowsHandlesPoliciesWithEmptyStringOrNoPipesOrOnePipeMissing(t *testing.T) {
	policies := []string{
		"",
		"1",
		"2|Control 2|Framework 2",
		"3|Control 3|Framework 3|Extra 3",
		"4||Framework 4",
		"|",
		"5|Control 5||Extra 5",
	}

	expectedRows := [][]string{
		{"", "", "https://hub.armosec.io/docs/", ""},
		{"1", "", "https://hub.armosec.io/docs/1", ""},
		{"2", "Control 2", "https://hub.armosec.io/docs/2", "Framework\n2"},
		{"3", "Control 3", "https://hub.armosec.io/docs/3", "Framework\n3"},
		{"4", "", "https://hub.armosec.io/docs/4", "Framework\n4"},
		{"", "", "https://hub.armosec.io/docs/", ""},
		{"5", "Control 5", "https://hub.armosec.io/docs/5", ""},
	}

	rows := generateControlRows(policies)

	assert.Equal(t, expectedRows, rows)
}

// The function generates a table with the correct headers and rows based on the input policies.
func TestGenerateTableWithCorrectHeadersAndRows(t *testing.T) {
	// Arrange
	ctx := context.Background()
	policies := []string{
		"1|Control 1|Framework 1",
		"2|Control 2|Framework 2",
		"3|Control 3|Framework 3",
	}

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	prettyPrintControls(ctx, policies)

	w.Close()
	got, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	// got := buf.String()
	want := `┌────────────┬──────────────┬───────────────────────────────┬────────────┐
│ Control ID │ Control name │ Docs                          │ Frameworks │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          1 │ Control 1    │ https://hub.armosec.io/docs/1 │ Framework  │
│            │              │                               │          1 │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          2 │ Control 2    │ https://hub.armosec.io/docs/2 │ Framework  │
│            │              │                               │          2 │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          3 │ Control 3    │ https://hub.armosec.io/docs/3 │ Framework  │
│            │              │                               │          3 │
└────────────┴──────────────┴───────────────────────────────┴────────────┘
`

	assert.Equal(t, want, string(got))
}

func TestGenerateTableWithMalformedPoliciesAndPrettyPrintHeadersAndRows(t *testing.T) {
	// Arrange
	ctx := context.Background()
	policies := []string{
		"",
		"1",
		"2|Control 2|Framework 2",
		"3|Control 3|Framework 3|Extra 3",
		"4||Framework 4",
		"|",
		"5|Control 5||Extra 5",
	}

	// Redirect stdout to a buffer
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	prettyPrintControls(ctx, policies)

	w.Close()
	got, _ := io.ReadAll(r)

	os.Stdout = rescueStdout

	want := `┌────────────┬──────────────┬───────────────────────────────┬────────────┐
│ Control ID │ Control name │ Docs                          │ Frameworks │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│            │              │ https://hub.armosec.io/docs/  │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          1 │              │ https://hub.armosec.io/docs/1 │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          2 │ Control 2    │ https://hub.armosec.io/docs/2 │ Framework  │
│            │              │                               │          2 │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          3 │ Control 3    │ https://hub.armosec.io/docs/3 │ Framework  │
│            │              │                               │          3 │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          4 │              │ https://hub.armosec.io/docs/4 │ Framework  │
│            │              │                               │          4 │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│            │              │ https://hub.armosec.io/docs/  │            │
├────────────┼──────────────┼───────────────────────────────┼────────────┤
│          5 │ Control 5    │ https://hub.armosec.io/docs/5 │            │
└────────────┴──────────────┴───────────────────────────────┴────────────┘
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
