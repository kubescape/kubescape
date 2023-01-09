package resourcehandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	urlA = "https://github.com/kubescape/kubescape"
	urlB = "https://github.com/kubescape/kubescape/blob/master/examples/online-boutique/adservice.yaml"
	urlC = "https://github.com/kubescape/kubescape/tree/master/examples/online-boutique"
	// urlD = "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml"
)

/*

TODO: tests were commented out due to actual http calls ; http calls should be mocked.

func TestScanRepository(t *testing.T) {
	{
		files, err := ScanRepository(urlA, "")
		assert.NoError(t, err)
		assert.Less(t, 0, len(files))
	}
	{
		files, err := ScanRepository(urlB, "")
		assert.NoError(t, err)
		assert.Less(t, 0, len(files))
	}
	{
		files, err := ScanRepository(urlC, "")
		assert.NoError(t, err)
		assert.Less(t, 0, len(files))
	}
	{
		files, err := ScanRepository(urlD, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(files))
	}

}

func TestGetHost(t *testing.T) {
	{
		host, err := getHost(urlA)
		assert.NoError(t, err)
		assert.Equal(t, "github.com", host)
	}
	{
		host, err := getHost(urlB)
		assert.NoError(t, err)
		assert.Equal(t, "github.com", host)
	}
	{
		host, err := getHost(urlC)
		assert.NoError(t, err)
		assert.Equal(t, "github.com", host)
	}
	{
		host, err := getHost(urlD)
		assert.NoError(t, err)
		assert.Equal(t, "raw.githubusercontent.com", host)
	}
}

func TestGithubSetBranch(t *testing.T) {
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlA))
		assert.NoError(t, gh.setBranch(""))
		assert.Equal(t, "master", gh.getBranch())
	}
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlB))
		err := gh.setBranch("dev")
		assert.NoError(t, err)
		assert.Equal(t, "dev", gh.getBranch())
	}
}

func TestGithubSetTree(t *testing.T) {
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlA))
		assert.NoError(t, gh.setBranch(""))
		err := gh.setTree()
		assert.NoError(t, err)
		assert.Less(t, 0, len(gh.getTree().InnerTrees))
	}
}
func TestGithubGetYamlFromTree(t *testing.T) {
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlA))
		assert.NoError(t, gh.setBranch(""))
		assert.NoError(t, gh.setTree())
		files := gh.getFilesFromTree([]string{"yaml"})
		assert.Less(t, 0, len(files))
	}
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlB))
		assert.NoError(t, gh.setBranch(""))
		assert.NoError(t, gh.setTree())
		files := gh.getFilesFromTree([]string{"yaml"})
		assert.Equal(t, 1, len(files))
	}
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlC))
		assert.NoError(t, gh.setBranch(""))
		assert.NoError(t, gh.setTree())
		files := gh.getFilesFromTree([]string{"yaml"})
		assert.Equal(t, 12, len(files))
	}
}
*/

func TestGithubParse(t *testing.T) {
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlA))
		assert.Equal(t, "kubescape/kubescape", joinOwnerNRepo(gh.owner, gh.repo))
	}
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlB))
		assert.Equal(t, "kubescape/kubescape", joinOwnerNRepo(gh.owner, gh.repo))
		assert.Equal(t, "master", gh.branch)
		assert.Equal(t, "examples/online-boutique/adservice.yaml", gh.path)
		assert.True(t, gh.isFile)
		assert.Equal(t, 1, len(gh.getFilesFromTree([]string{"yaml"})))
		assert.Equal(t, 0, len(gh.getFilesFromTree([]string{"yml"})))
	}
	{
		gh := NewGitHubRepository()
		assert.NoError(t, gh.parse(urlC))
		assert.Equal(t, "kubescape/kubescape", joinOwnerNRepo(gh.owner, gh.repo))
		assert.Equal(t, "master", gh.branch)
		assert.Equal(t, "examples/online-boutique", gh.path)
		assert.False(t, gh.isFile)
	}
}
