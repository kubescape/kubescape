package policyhandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
)

type IRepository interface {
	setBranch(string) error
	setTree() error
	getYamlFromTree() []string
}

type innerTree struct {
	Path string `json:"path"`
}
type tree struct {
	InnerTrees []innerTree `json:"tree"`
}

type GitHubRepository struct {
	host   string
	name   string // <org>/<repo>
	branch string
	tree   tree
}
type githubDefaultBranchAPI struct {
	DefaultBranch string `json:"default_branch"`
}

func NewGitHubRepository(rep string) *GitHubRepository {
	return &GitHubRepository{
		host: "github",
		name: rep,
	}
}

func ScanRepository(command string, branchOptional string) ([]string, error) {
	repo, err := getRepository(command)
	if err != nil {
		return nil, err
	}

	err = repo.setBranch(branchOptional)
	if err != nil {
		return nil, err
	}

	err = repo.setTree()
	if err != nil {
		return nil, err
	}

	// get all paths that are of the yaml type, and build them into a valid url
	return repo.getYamlFromTree(), nil
}

func getHostAndRepoName(url string) (string, string, error) {
	splitUrl := strings.Split(url, "/")

	if len(splitUrl) != 5 {
		return "", "", fmt.Errorf("failed to pars url: %s", url)
	}

	hostUrl := splitUrl[2]                                               // github.com, gitlab.com, etc.
	repository := splitUrl[3] + "/" + strings.Split(splitUrl[4], ".")[0] // user/reposetory

	return hostUrl, repository, nil
}

func getRepository(url string) (IRepository, error) {
	hostUrl, repoName, err := getHostAndRepoName(url)
	if err != nil {
		return nil, err
	}

	var repo IRepository
	switch repoHost := strings.Split(hostUrl, ".")[0]; repoHost {
	case "github":
		repo = NewGitHubRepository(repoName)
	default:
		return nil, fmt.Errorf("unknown repository host: %s", repoHost)
	}

	// Returns the host-url, and the part of the user and repository from the url
	return repo, nil
}

func (g *GitHubRepository) setBranch(branchOptional string) error {
	// Checks whether the repository type is a master or another type.
	// By default it is "master", unless the branchOptional came with a value
	if branchOptional == "" {

		body, err := getter.HttpGetter(&http.Client{}, g.defaultBranchAPI())
		if err != nil {
			return err
		}

		var data githubDefaultBranchAPI
		err = json.Unmarshal([]byte(body), &data)
		if err != nil {
			return err
		}
		g.branch = data.DefaultBranch
	} else {
		g.branch = branchOptional
	}
	return nil
}

func (g *GitHubRepository) defaultBranchAPI() string {
	return fmt.Sprintf("https://api.github.com/repos/%s", g.name)
}

func (g *GitHubRepository) setTree() error {
	body, err := getter.HttpGetter(&http.Client{}, g.treeAPI())
	if err != nil {
		return err
	}

	// press all tree to json
	var tree tree
	err = json.Unmarshal([]byte(body), &tree)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", g.treeAPI(), err.Error())
		// fmt.Printf("failed to unmarshal response body from '%s', reason: %s", urlCommand, err.Error())
		// return nil
	}
	g.tree = tree

	return nil
}

func (g *GitHubRepository) treeAPI() string {
	return fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", g.name, g.branch)
}

// return a list of yaml for a given repository tree
func (g *GitHubRepository) getYamlFromTree() []string {
	var urls []string
	for _, path := range g.tree.InnerTrees {
		if strings.HasSuffix(path.Path, ".yaml") {
			urls = append(urls, fmt.Sprintf("%s/%s", g.rowYamlUrl(), path.Path))
		}
	}
	return urls
}

func (g *GitHubRepository) rowYamlUrl() string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", g.name, g.branch)
}
