package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"errors"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/maruel/natural"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
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
	data, err := srv.ListFrameworks(t.Context(), "")
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
	data, err := srv.ListFrameworks(t.Context(), "")
	require.NoError(t, err)
	var names []string
	require.NoError(t, json.Unmarshal(data, &names))
	for i := 1; i < len(names); i++ {
		assert.True(t, natural.Less(names[i-1], names[i]) || names[i-1] == names[i], "frameworks must be sorted naturally")
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

	cfgTool, ok := toolMap["list_controls_config"]
	require.True(t, ok, "list_controls_config must be registered")
	require.NotNil(t, cfgTool.Annotations.ReadOnlyHint, "list_controls_config must have ReadOnlyHint annotation")
	assert.True(t, *cfgTool.Annotations.ReadOnlyHint)
	assert.Contains(t, cfgTool.InputSchema.Properties, "search", "list_controls_config schema must have search property")
	assert.Contains(t, cfgTool.InputSchema.Properties, "control_id", "list_controls_config schema must have control_id property")
}

type fakeControlsConfigGetter struct {
	getter.IPolicyGetter
	frameworksList []string
	controlsList   []string
	frameworks     []reporthandling.Framework
	controlInputs  map[string][]string
}

func (f *fakeControlsConfigGetter) ListFrameworks() ([]string, error) {
	return f.frameworksList, nil
}
func (f *fakeControlsConfigGetter) ListControls() ([]string, error) {
	return f.controlsList, nil
}
func (f *fakeControlsConfigGetter) GetFrameworks() ([]reporthandling.Framework, error) {
	return f.frameworks, nil
}
func (f *fakeControlsConfigGetter) GetControlsInputs(ctx context.Context, clusterName string) (map[string][]string, error) {
	return f.controlInputs, nil
}

func listControlsConfigServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }
	setConnectedToCluster = func(bool) {}

	s := server.NewMCPServer("test", "test")
	ks := &KubescapeMcpserver{s: s}
	createPolicyListingTools(ks)
	createSuggestFixTools(ks)
	createDiffReportsTools(ks)
	cfg := &fakeControlsConfigGetter{
		frameworksList: []string{"nsa", "mitre", "cis-v1.12.0", "cis-v1.2.0"},
		controlsList: []string{
			"C-0016|Ensure that only approved container images are used|cis-v1.2.0,nsa",
			"C-0050|Limit CPU and memory requests|cis-v1.2.0",
		},
		frameworks: []reporthandling.Framework{
			{
				Controls: []reporthandling.Control{
					{
						ControlID: "C-0016",
						Rules: []reporthandling.PolicyRule{
							{
								ControlConfigInputs: []reporthandling.ControlConfigInputs{
									{
										Path:        "settings.postureControlInputs.imageRepositoryAllowList",
										Name:        "Allowed image repositories",
										Description: "Repositories images may come from.",
									},
								},
							},
						},
					},
					{
						ControlID: "C-0050",
						Rules: []reporthandling.PolicyRule{
							{
								ControlConfigInputs: []reporthandling.ControlConfigInputs{
									{
										Path:        "settings.postureControlInputs.cpu_limit_max",
										Name:        "cpu_limit_max",
										Description: "Maximum allowed CPU limit.",
									},
								},
							},
						},
					},
				},
			},
		},
		controlInputs: map[string][]string{
			"imageRepositoryAllowList": {"docker.io", "quay.io"},
			"cpu_limit_max":            {"4"},
			"unboundSetting":           {"value1"},
		},
	}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return cfg })
	return ks
}

func TestListFrameworks_NaturalSorting(t *testing.T) {
	ks := listControlsConfigServer(t)
	data, err := ks.ListFrameworks(context.Background(), "")
	require.NoError(t, err)
	var names []string
	require.NoError(t, json.Unmarshal(data, &names))
	// In natural sorting, cis-v1.2.0 must appear before cis-v1.12.0
	assert.Equal(t, []string{"cis-v1.2.0", "cis-v1.12.0", "mitre", "nsa"}, names)
}

func TestListFrameworks_Search(t *testing.T) {
	ks := listControlsConfigServer(t)
	data, err := ks.ListFrameworks(context.Background(), "cis")
	require.NoError(t, err)
	var names []string
	require.NoError(t, json.Unmarshal(data, &names))
	assert.Equal(t, []string{"cis-v1.2.0", "cis-v1.12.0"}, names)

	data, err = ks.ListFrameworks(context.Background(), "NSA")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &names))
	assert.Equal(t, []string{"nsa"}, names)

	data, err = ks.ListFrameworks(context.Background(), "nonexistent")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &names))
	assert.Empty(t, names)
}

func TestListControlsConfig_AllEntries(t *testing.T) {
	ks := listControlsConfigServer(t)
	data, err := ks.ListControlsConfig(context.Background(), "", "")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 3)

	assert.Equal(t, "cpu_limit_max", entries[0].Name)
	assert.Equal(t, []string{"4"}, entries[0].Values)
	assert.Equal(t, []string{"C-0050"}, entries[0].Controls)

	assert.Equal(t, "imageRepositoryAllowList", entries[1].Name)
	assert.Equal(t, "Allowed image repositories", entries[1].Title)
	assert.Equal(t, "Repositories images may come from.", entries[1].Description)
	assert.Equal(t, []string{"docker.io", "quay.io"}, entries[1].Values)
	assert.Equal(t, []string{"C-0016"}, entries[1].Controls)

	assert.Equal(t, "unboundSetting", entries[2].Name)
	assert.Equal(t, []string{"value1"}, entries[2].Values)
	assert.Empty(t, entries[2].Controls)
}

func TestListControlsConfig_FilterByControlID(t *testing.T) {
	ks := listControlsConfigServer(t)
	data, err := ks.ListControlsConfig(context.Background(), "", "c-0016")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "imageRepositoryAllowList", entries[0].Name)

	data, err = ks.ListControlsConfig(context.Background(), "", "C-9999")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &entries))
	assert.Empty(t, entries)
}

func TestListControlsConfig_FilterBySearch(t *testing.T) {
	ks := listControlsConfigServer(t)
	// Search by description keyword
	data, err := ks.ListControlsConfig(context.Background(), "repositories", "")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "imageRepositoryAllowList", entries[0].Name)

	// Search by control ID substring
	data, err = ks.ListControlsConfig(context.Background(), "0050", "")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "cpu_limit_max", entries[0].Name)
}

func TestListControlsConfig_ViaCallTool(t *testing.T) {
	ks := listControlsConfigServer(t)
	res, err := ks.CallTool(context.Background(), "list_controls_config", map[string]any{"control_id": "C-0016"})
	require.NoError(t, err)
	require.False(t, res.IsError, toolResultText(t, res))
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "imageRepositoryAllowList", entries[0].Name)
}

func TestListFrameworks_ViaCallTool_WithSearch(t *testing.T) {
	ks := listControlsConfigServer(t)
	res, err := ks.CallTool(context.Background(), "list_frameworks", map[string]any{"search": "cis"})
	require.NoError(t, err)
	require.False(t, res.IsError, toolResultText(t, res))
	var names []string
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &names))
	assert.Equal(t, []string{"cis-v1.2.0", "cis-v1.12.0"}, names)
}

func TestListControlsConfig_CRDForbiddenReturnsError(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }
	setConnectedToCluster = func(bool) {}

	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	dyn.PrependReactor("get", "controlinputs", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "kubescape.io", Resource: "controlinputs"}, "default", errors.New("RBAC forbidden"))
	})

	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("test", "test"),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	cfg := &fakeControlsConfigGetter{}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return cfg })

	_, err := ks.ListControlsConfig(context.Background(), "", "")
	require.Error(t, err)
	assert.True(t, apierrors.IsForbidden(err), "forbidden error must be returned, not swallowed: %v", err)
}

func TestListControlsConfig_CRDNotFoundFallsBackToPolicyDefaults(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }
	setConnectedToCluster = func(bool) {}

	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("test", "test"),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	cfg := &fakeControlsConfigGetter{
		frameworks: []reporthandling.Framework{
			{
				Controls: []reporthandling.Control{
					{
						ControlID: "C-0050",
						Rules: []reporthandling.PolicyRule{
							{
								ControlConfigInputs: []reporthandling.ControlConfigInputs{
									{
										Path: "settings.postureControlInputs.cpu_limit_max",
										Name: "cpu_limit_max",
									},
								},
							},
						},
					},
				},
			},
		},
		controlInputs: map[string][]string{
			"cpu_limit_max": {"2"},
		},
	}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return cfg })

	data, err := ks.ListControlsConfig(context.Background(), "", "")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "cpu_limit_max", entries[0].Name)
	assert.Equal(t, []string{"2"}, entries[0].Values)
}

func TestListControlsConfig_CRDValuesUsed(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }
	setConnectedToCluster = func(bool) {}

	controlInputGVR := schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1",
		Resource: "controlinputs",
	}
	controlInputObj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "kubescape.io/v1",
			"kind":       "ControlInput",
			"metadata": map[string]any{
				"name": "default",
			},
			"spec": map[string]any{
				"controls": map[string]any{
					"cpu_limit_max": []any{"8"},
				},
			},
		},
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{controlInputGVR: "ControlInputList"},
		controlInputObj,
	)

	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("test", "test"),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	cfg := &fakeControlsConfigGetter{
		frameworks: []reporthandling.Framework{
			{
				Controls: []reporthandling.Control{
					{
						ControlID: "C-0050",
						Rules: []reporthandling.PolicyRule{
							{
								ControlConfigInputs: []reporthandling.ControlConfigInputs{
									{
										Path: "settings.postureControlInputs.cpu_limit_max",
										Name: "cpu_limit_max",
									},
								},
							},
						},
					},
				},
			},
		},
		controlInputs: map[string][]string{
			"cpu_limit_max": {"2"}, // Policy default should be overridden by CRD value ("8")
		},
	}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return cfg })

	data, err := ks.ListControlsConfig(context.Background(), "", "")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "cpu_limit_max", entries[0].Name)
	assert.Equal(t, []string{"8"}, entries[0].Values)
}

func TestListControlsConfig_CRDEmptyValuesUsed(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }
	setConnectedToCluster = func(bool) {}

	controlInputGVR := schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1",
		Resource: "controlinputs",
	}
	controlInputObj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "kubescape.io/v1",
			"kind":       "ControlInput",
			"metadata": map[string]any{
				"name": "default",
			},
			"spec": map[string]any{
				"controls": map[string]any{},
			},
		},
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{controlInputGVR: "ControlInputList"},
		controlInputObj,
	)

	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("test", "test"),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	cfg := &fakeControlsConfigGetter{
		frameworks: []reporthandling.Framework{
			{
				Controls: []reporthandling.Control{
					{
						ControlID: "C-0050",
						Rules: []reporthandling.PolicyRule{
							{
								ControlConfigInputs: []reporthandling.ControlConfigInputs{
									{
										Path: "settings.postureControlInputs.cpu_limit_max",
										Name: "cpu_limit_max",
									},
								},
							},
						},
					},
				},
			},
		},
		controlInputs: map[string][]string{
			"cpu_limit_max": {"2"}, // Should NOT be used when cluster CRD exists with empty controls
		},
	}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return cfg })

	data, err := ks.ListControlsConfig(context.Background(), "", "")
	require.NoError(t, err)
	var entries []metav1.ControlConfigEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "cpu_limit_max", entries[0].Name)
	assert.Empty(t, entries[0].Values)
}
