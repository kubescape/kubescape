package mcpserver

import (
	"encoding/json"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
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
	data, err := srv.ListControls(t.Context())
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
	data, err := srv.ListControls(t.Context())
	if err != nil {
		t.Skipf("skipping: could not download controls (no network?): %v", err)
	}
	var entries []metav1.ControlListEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	for i := 1; i < len(entries); i++ {
		assert.LessOrEqual(t, entries[i-1].ID, entries[i].ID, "controls must be sorted by ID")
	}
}
