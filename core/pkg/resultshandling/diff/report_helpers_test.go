package diff

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsJSONNull(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{name: "exact null", raw: json.RawMessage(`null`), want: true},
		{name: "null with surrounding whitespace", raw: json.RawMessage(" \t null \n "), want: true},
		{name: "quoted null string is not null", raw: json.RawMessage(`"null"`), want: false},
		{name: "empty object", raw: json.RawMessage(`{}`), want: false},
		{name: "empty raw message", raw: json.RawMessage(``), want: false},
		{name: "nil raw message", raw: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isJSONNull(tt.raw))
		})
	}
}

func TestDifferentNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  bool
	}{
		{name: "distinct non-empty values", left: "cluster-a", right: "cluster-b", want: true},
		{name: "equal after trimming", left: " cluster-a ", right: "cluster-a", want: false},
		{name: "left empty", left: "", right: "cluster-b", want: false},
		{name: "right whitespace only", left: "cluster-a", right: "   ", want: false},
		{name: "both empty", left: "", right: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, differentNonEmpty(tt.left, tt.right))
		})
	}
}

func TestCanonicalSet(t *testing.T) {
	assert.Equal(t, []string{"default", "prod"}, canonicalSet([]string{" prod ", "default", "", "prod", "   "}))
	assert.Empty(t, canonicalSet(nil))
	assert.Empty(t, canonicalSet([]string{"", " \t "}))
}

func TestCompareStringSet(t *testing.T) {
	t.Run("both empty appends no reason", func(t *testing.T) {
		var reasons []string
		compareStringSet(&reasons, "namespaces", nil, []string{})
		assert.Empty(t, reasons)
	})

	t.Run("equivalent sets regardless of order or duplicates append no reason", func(t *testing.T) {
		var reasons []string
		compareStringSet(&reasons, "namespaces", []string{"prod", "default", "prod"}, []string{" default ", "prod"})
		assert.Empty(t, reasons)
	})

	t.Run("different sets append formatted reason", func(t *testing.T) {
		var reasons []string
		compareStringSet(&reasons, "namespaces", []string{"default"}, []string{"prod"})
		require.Len(t, reasons, 1)
		assert.Equal(t, "namespaces differ: base=[default] head=[prod]", reasons[0])
	})
}

func TestRepositoryIdentity(t *testing.T) {
	tests := []struct {
		name string
		repo *repoContext
		want string
	}{
		{name: "nil repo context", repo: nil, want: ""},
		{
			name: "provider owner and repo normalized to lowercase",
			repo: &repoContext{Provider: " GitHub ", Owner: " Kubescape ", Repo: " Kubescape "},
			want: "github/kubescape/kubescape",
		},
		{
			name: "owner and repo without provider trims leading slash",
			repo: &repoContext{Owner: "Org", Repo: "App"},
			want: "org/app",
		},
		{
			name: "falls back to normalized remote URL without .git suffix",
			repo: &repoContext{RemoteURL: " HTTPS://GitHub.com/kubescape/kubescape.git "},
			want: "https://github.com/kubescape/kubescape",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, repositoryIdentity(tt.repo))
		})
	}
}
