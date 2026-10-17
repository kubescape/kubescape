package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePolicyPipe_Empty(t *testing.T) {
	entry := parsePolicyPipe("")
	assert.Equal(t, "", entry.ID)
	assert.Equal(t, "", entry.Name)
	assert.Empty(t, entry.Frameworks)
}

func TestParsePolicyPipe_IDOnly(t *testing.T) {
	entry := parsePolicyPipe("C-0012")
	assert.Equal(t, "C-0012", entry.ID)
	assert.Equal(t, "", entry.Name)
	assert.Empty(t, entry.Frameworks)
}

func TestParsePolicyPipe_IDAndName(t *testing.T) {
	entry := parsePolicyPipe("C-0012|Applications credentials in configuration files")
	assert.Equal(t, "C-0012", entry.ID)
	assert.Equal(t, "Applications credentials in configuration files", entry.Name)
	assert.Empty(t, entry.Frameworks)
}

func TestParsePolicyPipe_FullEntry(t *testing.T) {
	entry := parsePolicyPipe("C-0012|Applications credentials in configuration files|nsa, mitre")
	assert.Equal(t, "C-0012", entry.ID)
	assert.Equal(t, "Applications credentials in configuration files", entry.Name)
	assert.Equal(t, []string{"nsa", "mitre"}, entry.Frameworks)
}

func TestParsePolicyPipe_SingleFramework(t *testing.T) {
	entry := parsePolicyPipe("C-0017|Immutable container filesystem|nsa")
	assert.Equal(t, "C-0017", entry.ID)
	assert.Equal(t, "Immutable container filesystem", entry.Name)
	assert.Equal(t, []string{"nsa"}, entry.Frameworks)
}

func TestParsePolicyPipe_FrameworksWithSpaces(t *testing.T) {
	entry := parsePolicyPipe("C-0030|Ingress and Egress blocked| nsa ,  mitre ")
	assert.Equal(t, "C-0030", entry.ID)
	assert.Equal(t, "Ingress and Egress blocked", entry.Name)
	assert.Equal(t, []string{"nsa", "mitre"}, entry.Frameworks)
}

func TestListFrameworks_ReturnsJSON(t *testing.T) {
	srv := &KubescapeMcpserver{}
	data, err := srv.ListFrameworks(t.Context())
	require.NoError(t, err)
	var names []string
	require.NoError(t, json.Unmarshal(data, &names), "output must be a JSON array of strings")
	assert.NotEmpty(t, names, "should return at least the native frameworks on fallback")
}

func TestListControls_ReturnsJSON(t *testing.T) {
	srv := &KubescapeMcpserver{}
	data, err := srv.ListControls(t.Context(), "")
	if err != nil {
		t.Skipf("skipping: could not download controls (no network?): %v", err)
	}
	var entries []metav1.ControlListEntry
	require.NoError(t, json.Unmarshal(data, &entries), "output must be a JSON array of ControlListEntry")
	for _, e := range entries {
		assert.NotEmpty(t, e.ID, "every entry must have an ID")
	}
}

func TestListFrameworks_IsSorted(t *testing.T) {
	srv := &KubescapeMcpserver{}
	data, err := srv.ListFrameworks(t.Context())
	require.NoError(t, err)
	var names []string
	require.NoError(t, json.Unmarshal(data, &names))
	for i := 1; i < len(names); i++ {
		assert.LessOrEqual(t, names[i-1], names[i], "frameworks must be sorted")
	}
}

func TestListControls_IsSorted(t *testing.T) {
	srv := &KubescapeMcpserver{}
	data, err := srv.ListControls(t.Context(), "")
	if err != nil {
		t.Skipf("skipping: could not download controls (no network?): %v", err)
	}
	var entries []metav1.ControlListEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	for i := 1; i < len(entries); i++ {
		assert.LessOrEqual(t, entries[i-1].ID, entries[i].ID, "controls must be sorted by ID")
	}
}

func TestFilterControlsByFramework(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Frameworks: []string{"AllControls"}},
		{ID: "C-0012", Frameworks: []string{"AllControls", "NSA", "MITRE"}},
		{ID: "C-0017", Frameworks: []string{"AllControls", "NSA"}},
		{ID: "C-0030", Frameworks: []string{}},
	}
	ids := func(es []metav1.ControlListEntry) []string {
		out := []string{}
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}

	got, err := filterControlsByFramework(entries, "", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017", "C-0030"}, ids(got), "no framework keeps every control")

	got, err = filterControlsByFramework(entries, "NSA", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"C-0012", "C-0017"}, ids(got))

	got, err = filterControlsByFramework(entries, "mitre", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"C-0012"}, ids(got), "matching is case-insensitive")

	catalog := []string{"NSA", "MITRE", "SOC2"}
	got, err = filterControlsByFramework(entries, "soc2", catalog)
	require.NoError(t, err, "a catalog framework with no controls is not an error")
	assert.Empty(t, got)
	assert.NotNil(t, got, "and it is an empty list, not null")

	got, err = filterControlsByFramework(entries, "allcontrols", catalog)
	require.NoError(t, err)
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017", "C-0030"}, ids(got), "AllControls is every control, tagged or not")

	got, err = filterControlsByFramework([]metav1.ControlListEntry{{ID: "C-0001", Frameworks: []string{"ClusterScan"}}}, "clusterscan", catalog)
	require.NoError(t, err, "a framework only seen on controls is known too")
	assert.Equal(t, []string{"C-0001"}, ids(got))

	_, err = filterControlsByFramework(entries, "PCI", catalog)
	var unknown *unknownFrameworkError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, []string{"AllControls", "MITRE", "NSA", "SOC2"}, unknown.supported)
	assert.Contains(t, err.Error(), `unknown framework "PCI"`)
}

func listControlsServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	ks := &KubescapeMcpserver{}
	ks.startPolicyLoad(func() getter.IPolicyGetter {
		return &fakePolicyGetter{frameworks: []string{"NSA", "MITRE", "SOC2"}, controls: []string{
			"C-0017|Immutable container filesystem|AllControls,NSA",
			"C-0001|Forbidden Container Registries|AllControls",
			"C-0012|Applications credentials in configuration files|AllControls,NSA,MITRE",
		}}
	})
	return ks
}

func listControlIDs(t *testing.T, ks *KubescapeMcpserver, args map[string]any) []string {
	t.Helper()
	result, err := ks.CallTool(context.Background(), "list_controls", args)
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var entries []metav1.ControlListEntry
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &entries))
	out := []string{}
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

func TestListControlsTool_FrameworkFilter(t *testing.T) {
	ks := listControlsServer(t)
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{}))
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"framework": nil}), "null is treated as absent")
	assert.Equal(t, []string{"C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"framework": "nsa"}))
	assert.Equal(t, []string{"C-0012"}, listControlIDs(t, ks, map[string]any{"framework": " MITRE "}), "surrounding spaces are trimmed")
	assert.Equal(t, []string{}, listControlIDs(t, ks, map[string]any{"framework": "SOC2"}), "a catalog framework with no controls returns []")
}

func TestListControlsTool_InvalidFramework(t *testing.T) {
	ks := listControlsServer(t)

	result, err := ks.CallTool(context.Background(), "list_controls", map[string]any{"framework": "PCI"})
	require.NoError(t, err)
	require.True(t, result.IsError)
	var toolErr struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	}
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	assert.Equal(t, string(ErrCodeInvalidArgument), toolErr.Code)
	assert.Equal(t, "framework", toolErr.Details["argument"])
	assert.Equal(t, []any{"AllControls", "MITRE", "NSA", "SOC2"}, toolErr.Details["supported_values"])

	result, err = ks.CallTool(context.Background(), "list_controls", map[string]any{"framework": 7})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "framework argument must be a string")
}

// The cached-policy fallback uses getter.LoadPolicy, whose control entries
// never carry the AllControls tag.
func TestListControlsTool_FrameworkFilterLocalPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}
	paths := []string{
		write("allcontrols.json", `{"name":"AllControls","controls":[{"controlID":"C-0001","name":"Forbidden Container Registries"},{"controlID":"C-0012","name":"Applications credentials in configuration files"}]}`),
		write("nsa.json", `{"name":"NSA","controls":[{"controlID":"C-0012","name":"Applications credentials in configuration files"}]}`),
	}
	ks := &KubescapeMcpserver{}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return getter.NewLoadPolicy(paths) })

	assert.Equal(t, []string{"C-0001", "C-0012"}, listControlIDs(t, ks, map[string]any{}))
	assert.Equal(t, []string{"C-0001", "C-0012"}, listControlIDs(t, ks, map[string]any{"framework": "AllControls"}))
	assert.Equal(t, []string{"C-0012"}, listControlIDs(t, ks, map[string]any{"framework": "nsa"}))
}
