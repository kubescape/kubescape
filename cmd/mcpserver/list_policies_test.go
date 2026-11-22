package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/maruel/natural"
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
	data, err := srv.ListControls(t.Context(), "", "", defaultControlsListLimit, 0)
	if err != nil {
		t.Skipf("skipping: could not download controls (no network?): %v", err)
	}
	var response controlsListResponse
	require.NoError(t, json.Unmarshal(data, &response), "output must be a paginated controls response")
	for _, e := range response.Controls {
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
	data, err := srv.ListControls(t.Context(), "", "", defaultControlsListLimit, 0)
	if err != nil {
		t.Skipf("skipping: could not download controls (no network?): %v", err)
	}
	var response controlsListResponse
	require.NoError(t, json.Unmarshal(data, &response))
	for i := 1; i < len(response.Controls); i++ {
		assert.True(t, natural.Less(response.Controls[i-1].ID, response.Controls[i].ID) || response.Controls[i-1].ID == response.Controls[i].ID, "controls must be naturally sorted by ID")
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

func listControls(t *testing.T, ks *KubescapeMcpserver, args map[string]any) controlsListResponse {
	t.Helper()
	result, err := ks.CallTool(context.Background(), "list_controls", args)
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var response controlsListResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &response))
	return response
}

func listControlIDs(t *testing.T, ks *KubescapeMcpserver, args map[string]any) []string {
	t.Helper()
	response := listControls(t, ks, args)
	out := make([]string, 0, len(response.Controls))
	for _, e := range response.Controls {
		out = append(out, e.ID)
	}
	return out
}

func TestListControlsTool_FrameworkFilter(t *testing.T) {
	ks := listControlsServer(t)
	defaultPage := listControls(t, ks, map[string]any{})
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{}))
	assert.Equal(t, 3, defaultPage.Total)
	assert.Equal(t, 3, defaultPage.Returned)
	assert.False(t, defaultPage.Truncated)
	assert.Nil(t, defaultPage.NextOffset)
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"framework": nil}), "null is treated as absent")
	assert.Equal(t, []string{"C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"framework": "nsa"}))
	assert.Equal(t, []string{"C-0012"}, listControlIDs(t, ks, map[string]any{"framework": " MITRE "}), "surrounding spaces are trimmed")
	assert.Equal(t, []string{}, listControlIDs(t, ks, map[string]any{"framework": "SOC2"}), "a catalog framework with no controls returns []")
	filteredPage := listControls(t, ks, map[string]any{"framework": "NSA", "limit": float64(1)})
	assert.Equal(t, 2, filteredPage.Total)
	assert.Equal(t, 1, filteredPage.Returned)
	assert.True(t, filteredPage.Truncated)
	assert.Equal(t, "C-0012", filteredPage.Controls[0].ID)
}

func TestListControlsTool_Paging(t *testing.T) {
	ks := listControlsServer(t)
	first := listControls(t, ks, map[string]any{"limit": float64(2)})
	assert.Equal(t, 3, first.Total)
	assert.Equal(t, 2, first.Returned)
	assert.True(t, first.Truncated)
	require.NotNil(t, first.NextOffset)
	assert.Equal(t, 2, *first.NextOffset)
	assert.Equal(t, []string{"C-0001", "C-0012"}, listControlIDs(t, ks, map[string]any{"limit": float64(2)}))

	second := listControls(t, ks, map[string]any{"limit": float64(2), "offset": float64(*first.NextOffset)})
	require.Len(t, second.Controls, 1)
	assert.Equal(t, "C-0017", second.Controls[0].ID)
	assert.False(t, second.Truncated)
	assert.Nil(t, second.NextOffset)

	pastEnd := listControls(t, ks, map[string]any{"offset": float64(10)})
	assert.Equal(t, 3, pastEnd.Total)
	assert.Equal(t, 0, pastEnd.Returned)
	assert.NotNil(t, pastEnd.Controls)
}

func TestListControlsTool_InvalidPaging(t *testing.T) {
	ks := listControlsServer(t)
	for _, args := range []map[string]any{
		{"limit": float64(0)},
		{"limit": float64(maxControlsListLimit + 1)},
		{"limit": 1.5},
		{"offset": float64(-1)},
		{"offset": "1"},
	} {
		result, err := ks.CallTool(context.Background(), "list_controls", args)
		require.NoError(t, err)
		assert.True(t, result.IsError, "args: %#v", args)
	}
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

func TestFilterControlsBySearch(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Forbidden Container Registries", Frameworks: []string{"AllControls"}},
		{ID: "C-0012", Name: "Applications credentials in configuration files", Frameworks: []string{"AllControls", "NSA", "MITRE"}},
		{ID: "C-0017", Name: "Immutable container filesystem", Frameworks: []string{"AllControls", "NSA"}},
		{ID: "C-0030", Name: "Ingress and Egress blocked", Frameworks: []string{}},
	}
	ids := func(es []metav1.ControlListEntry) []string {
		out := make([]string, 0, len(es))
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}

	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017", "C-0030"}, ids(filterControlsBySearch(entries, "")))
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017", "C-0030"}, ids(filterControlsBySearch(entries, "   ")))
	assert.Equal(t, []string{"C-0017"}, ids(filterControlsBySearch(entries, "c-0017")), "matching by ID is case-insensitive")
	assert.Equal(t, []string{"C-0001", "C-0017"}, ids(filterControlsBySearch(entries, "container")), "matching by Name")
	assert.Equal(t, []string{"C-0012"}, ids(filterControlsBySearch(entries, "CREDENTIALS")), "matching by Name is case-insensitive")
	assert.Equal(t, []string{"C-0012"}, ids(filterControlsBySearch(entries, "mitre")), "matching by Framework")
	noMatches := filterControlsBySearch(entries, "nonexistent-keyword")
	assert.Empty(t, noMatches)
	assert.NotNil(t, noMatches, "no match returns empty slice, not nil")
}

func TestListControlsTool_Search(t *testing.T) {
	ks := listControlsServer(t)

	// Search matching multiple controls by name
	page := listControls(t, ks, map[string]any{"search": "container"})
	assert.Equal(t, 2, page.Total)
	assert.Equal(t, 2, page.Returned)
	assert.Equal(t, []string{"C-0001", "C-0017"}, listControlIDs(t, ks, map[string]any{"search": "container"}))

	// Search matching single control by ID
	assert.Equal(t, []string{"C-0012"}, listControlIDs(t, ks, map[string]any{"search": "c-0012"}))

	// Search matching by framework
	assert.Equal(t, []string{"C-0012"}, listControlIDs(t, ks, map[string]any{"search": "mitre"}))

	// Search with null or whitespace is treated as absent
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"search": nil}))
	assert.Equal(t, []string{"C-0001", "C-0012", "C-0017"}, listControlIDs(t, ks, map[string]any{"search": "  "}))

	// Combined framework and search
	// C-0001 has "container" in name but is not in NSA. Only C-0017 matches both.
	assert.Equal(t, []string{"C-0017"}, listControlIDs(t, ks, map[string]any{"framework": "nsa", "search": "container"}))

	// Search with paging
	paged := listControls(t, ks, map[string]any{"search": "container", "limit": float64(1)})
	assert.Equal(t, 2, paged.Total)
	assert.Equal(t, 1, paged.Returned)
	assert.True(t, paged.Truncated)
	require.NotNil(t, paged.NextOffset)
	assert.Equal(t, 1, *paged.NextOffset)
	assert.Equal(t, "C-0001", paged.Controls[0].ID)

	pagedNext := listControls(t, ks, map[string]any{"search": "container", "limit": float64(1), "offset": float64(*paged.NextOffset)})
	assert.Equal(t, 2, pagedNext.Total)
	assert.Equal(t, 1, pagedNext.Returned)
	assert.False(t, pagedNext.Truncated)
	assert.Nil(t, pagedNext.NextOffset)
	assert.Equal(t, "C-0017", pagedNext.Controls[0].ID)

	// Search with no matches returns empty list
	empty := listControls(t, ks, map[string]any{"search": "nonexistent"})
	assert.Equal(t, 0, empty.Total)
	assert.Equal(t, 0, empty.Returned)
	assert.False(t, empty.Truncated)
	assert.Empty(t, empty.Controls)
	assert.NotNil(t, empty.Controls)

	// Invalid search argument type returns error
	result, err := ks.CallTool(context.Background(), "list_controls", map[string]any{"search": 123})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "search argument must be a string")
}

func TestListControlsTool_NaturalSort(t *testing.T) {
	ks := &KubescapeMcpserver{}
	ks.startPolicyLoad(func() getter.IPolicyGetter {
		return &fakePolicyGetter{frameworks: []string{"CIS"}, controls: []string{
			"CIS-1.1.10|Disable automounting service account tokens|CIS",
			"CIS-1.1.2|Ensure that the permissions on the file are configured|CIS",
			"CIS-1.1.1|Ensure that the API server pod specification file permissions are set|CIS",
		}}
	})

	// Standard lexical sort puts CIS-1.1.10 before CIS-1.1.2.
	// Natural sort puts CIS-1.1.1, CIS-1.1.2, CIS-1.1.10 in numeric sequence.
	assert.Equal(t, []string{"CIS-1.1.1", "CIS-1.1.2", "CIS-1.1.10"}, listControlIDs(t, ks, map[string]any{}))
}

func TestListPolicyTools_RegistrationAndAnnotations(t *testing.T) {
	s := server.NewMCPServer("test", "0.0.1", server.WithToolCapabilities(false))
	createPolicyListingTools(&KubescapeMcpserver{s: s})

	resp := s.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	toolMap := make(map[string]mcp.Tool)
	for _, tool := range parsed.Result.Tools {
		toolMap[tool.Name] = tool
	}

	fwTool, ok := toolMap["list_frameworks"]
	require.True(t, ok, "list_frameworks must be registered")
	require.NotNil(t, fwTool.Annotations.ReadOnlyHint, "list_frameworks must have ReadOnlyHint annotation")
	assert.True(t, *fwTool.Annotations.ReadOnlyHint)

	ctrlTool, ok := toolMap["list_controls"]
	require.True(t, ok, "list_controls must be registered")
	require.NotNil(t, ctrlTool.Annotations.ReadOnlyHint, "list_controls must have ReadOnlyHint annotation")
	assert.True(t, *ctrlTool.Annotations.ReadOnlyHint)
	assert.Contains(t, ctrlTool.InputSchema.Properties, "search", "list_controls schema must have search property")
	assert.Contains(t, ctrlTool.InputSchema.Properties, "framework", "list_controls schema must have framework property")
}
