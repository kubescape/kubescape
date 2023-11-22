package resourcehandler

import (
	"errors"
	"fmt"
	"os"
	"testing"

	giturl "github.com/kubescape/go-git-url"
	"github.com/stretchr/testify/assert"
)

func TestIsGitRepoPublic(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{
			url:  "https://github.com/kubescape/kubescape/",
			want: true,
		},
		{
			url:  "http://invalidurl",
			want: false,
		},
		{
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, isGitRepoPublic(tt.url))
		})
	}
}

func TestGetProviderError(t *testing.T) {
	tests := []struct {
		url string
		err error
	}{
		{
			url: "https://github.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("GITHUB_TOKEN is not present")),
		},
		{
			url: "https://gitlab.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("GITLAB_TOKEN is not present")),
		},
		{
			url: "https://dev.azure.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("AZURE_TOKEN is not present")),
		},
		{
			url: "https://bitbucket.org/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("BITBUCKET_TOKEN is not present")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			gitURL, _ := giturl.NewGitAPI(tt.url)
			assert.Equal(t, tt.err, getProviderError(gitURL))
		})
	}
}

func TestCloneRepo(t *testing.T) {
	tests := []struct {
		url string
		err error
	}{
		{
			url: "https://github.com/kubescape/kubescape/",
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("failed to create temporary directory: %v", err)
			}

			gitURL, _ := giturl.NewGitAPI(tt.url)
			tempDir, err := cloneRepo(gitURL)
			assert.NotEqual(t, tmpDir, tempDir)
			assert.Equal(t, tt.err, err)
		})
	}
}
