package cautils

import (
	"context"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetContextMetadata(t *testing.T) {
	{
		ctx := reporthandlingv2.ContextMetadata{}
		scanInfo := &ScanInfo{}
		scanInfo.setContextMetadata(context.TODO(), &ctx)

		assert.NotNil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)
	}
	// TODO: tests were commented out due to actual http calls ; http calls should be mocked.
	/*{
		ctx := reporthandlingv2.ContextMetadata{}
		setContextMetadata(&ctx, "https://github.com/kubescape/kubescape")
		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.NotNil(t, ctx.RepoContextMetadata)
		assert.Equal(t, "kubescape", ctx.RepoContextMetadata.Repo)
		assert.Equal(t, "kubescape", ctx.RepoContextMetadata.Owner)
		assert.Equal(t, "master", ctx.RepoContextMetadata.Branch)
	}*/
}

func TestGetHostname(t *testing.T) {
	// Test that the hostname is not empty
	assert.NotEqual(t, "", getHostname())
}

func TestGetScanningContext(t *testing.T) {
	repoRoot, err := os.MkdirTemp("", "repo")
	require.NoError(t, err)
	defer func(name string) {
		_ = os.Remove(name)
	}(repoRoot)
	_, err = git.PlainClone(repoRoot, false, &git.CloneOptions{
		URL: "https://github.com/kubescape/http-request",
	})
	require.NoError(t, err)
	tmpFile, err := os.CreateTemp("", "single.*.txt")
	require.NoError(t, err)
	defer func(name string) {
		_ = os.Remove(name)
	}(tmpFile.Name())
	tests := []struct {
		name  string
		input string
		want  ScanningContext
	}{
		{
			name:  "empty input",
			input: "",
			want:  ContextCluster,
		},
		{
			name:  "git URL input",
			input: "https://github.com/kubescape/http-request",
			want:  ContextGitLocal,
		},
		{
			name:  "local git input",
			input: repoRoot,
			want:  ContextGitLocal,
		},
		{
			name:  "single file input",
			input: tmpFile.Name(),
			want:  ContextFile,
		},
		{
			name:  "directory input",
			input: os.TempDir(),
			want:  ContextDir,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &ScanInfo{}
			assert.Equalf(t, tt.want, scanInfo.getScanningContext(tt.input), "GetScanningContext(%v)", tt.input)
		})
	}
}

func TestScanInfoFormats(t *testing.T) {
	testCases := []struct {
		Input string
		Want  []string
	}{
		{"", []string{}},
		{"json", []string{"json"}},
		{"pdf", []string{"pdf"}},
		{"html", []string{"html"}},
		{"sarif", []string{"sarif"}},
		{"html,pdf,sarif", []string{"html", "pdf", "sarif"}},
		{"pretty-printer,pdf,sarif", []string{"pretty-printer", "pdf", "sarif"}},
	}

	for _, tc := range testCases {
		t.Run(tc.Input, func(t *testing.T) {
			input := tc.Input
			want := tc.Want
			scanInfo := &ScanInfo{Format: input}

			got := scanInfo.Formats()

			assert.Equal(t, want, got)
		})
	}
}
