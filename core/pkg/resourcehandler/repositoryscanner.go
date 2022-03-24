package resourcehandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/armosec/kubescape/core/cautils/getter"
	giturls "github.com/whilp/git-urls"
	"k8s.io/utils/strings/slices"
)

type IRepository interface {
	parse(fullURL string) error

	setBranch(string) error
	setTree() error

	getBranch() string
	getTree() tree

	getFilesFromTree([]string) []string
}

type innerTree struct {
	Path string `json:"path"`
}
type tree struct {
	InnerTrees []innerTree `json:"tree"`
}

type GitHubRepository struct {
	// name   string // <org>/<repo>
	host   string
	owner  string //
	repo   string //
	branch string
	path   string
	isFile bool
	tree   tree
}
type githubDefaultBranchAPI struct {
	DefaultBranch string `json:"default_branch"`
}

func NewGitHubRepository() *GitHubRepository {
	return &GitHubRepository{
		host: "github.com",
		// name: rep,
	}
}

func ScanRepository(command string, branchOptional string) ([]string, error) {
	repo, err := getRepository(command)
	if err != nil {
		return nil, err
	}

	if err := repo.parse(command); err != nil {
		return nil, err
	}

	if err := repo.setBranch(branchOptional); err != nil {
		return nil, err
	}

	if err := repo.setTree(); err != nil {
		return nil, err
	}

	// get all paths that are of the yaml type, and build them into a valid url
	return repo.getFilesFromTree([]string{"yaml", "yml", "json"}), nil
}

func getHost(fullURL string) (string, error) {
	parsedURL, err := giturls.Parse(fullURL)
	if err != nil {
		return "", err
	}

	return parsedURL.Host, nil
}

// func parseHostAndRepoName(fullURL string) (string, string, error) {
// 	parsedURL, err := giturls.Parse(fullURL)
// 	if err != nil {
// 		return "", "", err
// 	}

// 	host := parsedURL.Host

// 	splittedRepo := strings.FieldsFunc(parsedURL.Path, func(c rune) bool { return c == '/' })
// 	if len(splittedRepo) < 2 {
// 		return "", "", fmt.Errorf("expecting <user>/<repo> in url path, received: '%s'", parsedURL.Path)
// 	}
// 	return host, fmt.Sprintf("%s/%s", splittedRepo[0], splittedRepo[1]), nil
// }

func getRepository(fullURL string) (IRepository, error) {
	hostUrl, err := getHost(fullURL)
	if err != nil {
		return nil, err
	}

	var repo IRepository
	switch hostUrl {
	case "github.com", "raw.githubusercontent.com":
		repo = NewGitHubRepository()
	default:
		return nil, fmt.Errorf("unknown repository host: %s", hostUrl)
	}

	// Returns the host-url, and the part of the user and repository from the url
	return repo, nil
}
func (g *GitHubRepository) parse(fullURL string) error {
	parsedURL, err := giturls.Parse(fullURL)
	if err != nil {
		return err
	}

	splittedRepo := strings.FieldsFunc(parsedURL.Path, func(c rune) bool { return c == '/' })
	if len(splittedRepo) < 2 {
		return fmt.Errorf("expecting <user>/<repo> in url path, received: '%s'", parsedURL.Path)
	}
	g.owner = splittedRepo[0]
	g.repo = splittedRepo[1]

	// root of repo
	if len(splittedRepo) < 4 {
		return nil
	}

	// is file or dir
	switch splittedRepo[2] {
	case "blob":
		g.isFile = true
	case "tree":
		g.isFile = false
	default:
		// Unknown - failed to parse
		return nil
	}
	g.branch = splittedRepo[3]

	if len(splittedRepo) < 5 {
		return nil
	}
	g.path = strings.Join(splittedRepo[4:], "/")

	return nil
}

func (g *GitHubRepository) getBranch() string { return g.branch }
func (g *GitHubRepository) getTree() tree     { return g.tree }

func (g *GitHubRepository) setBranch(branchOptional string) error {
	// Checks whether the repository type is a master or another type.
	// By default it is "master", unless the branchOptional came with a value
	if branchOptional != "" {
		g.branch = branchOptional
	}
	if g.branch != "" {
		return nil
	}
	body, err := getter.HttpGetter(&http.Client{}, g.defaultBranchAPI(), nil)
	if err != nil {
		return err
	}

	var data githubDefaultBranchAPI
	err = json.Unmarshal([]byte(body), &data)
	if err != nil {
		return err
	}
	g.branch = data.DefaultBranch
	return nil
}

func joinOwnerNRepo(owner, repo string) string {
	return fmt.Sprintf("%s/%s", owner, repo)
}
func (g *GitHubRepository) defaultBranchAPI() string {
	return fmt.Sprintf("https://api.github.com/repos/%s", joinOwnerNRepo(g.owner, g.repo))
}

func (g *GitHubRepository) setTree() error {
	body, err := getter.HttpGetter(&http.Client{}, g.treeAPI(), nil)
	if err != nil {
		return err
	}

	// press all tree to json
	var tree tree
	err = json.Unmarshal([]byte(body), &tree)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", g.treeAPI(), err.Error())
		// return nil
	}
	g.tree = tree

	return nil
}

func (g *GitHubRepository) treeAPI() string {
	return fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", joinOwnerNRepo(g.owner, g.repo), g.branch)
}

// return a list of yaml for a given repository tree
func (g *GitHubRepository) getFilesFromTree(filesExtensions []string) []string {
	var urls []string
	if g.isFile {
		return []string{fmt.Sprintf("%s/%s", g.rowYamlUrl(), g.path)}
	}
	for _, path := range g.tree.InnerTrees {
		if g.path != "" && !strings.HasPrefix(path.Path, g.path) {
			continue
		}
		if slices.Contains(filesExtensions, getFileExtension(path.Path)) {
			urls = append(urls, fmt.Sprintf("%s/%s", g.rowYamlUrl(), path.Path))
		}
	}
	return urls
}

func (g *GitHubRepository) rowYamlUrl() string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", joinOwnerNRepo(g.owner, g.repo), g.branch)
}

func getFileExtension(path string) string {
	return strings.TrimPrefix(filepath.Ext(path), ".")
}
