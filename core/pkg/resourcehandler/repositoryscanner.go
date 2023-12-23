package resourcehandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"k8s.io/utils/strings/slices"
)

type IRepository interface {
	parse(fullURL string) error

	setBranch(string) error
	setTree() error
	setIsFile(bool)

	getIsFile() bool
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
	token  string
	isFile bool
	tree   tree
}
type githubDefaultBranchAPI struct {
	DefaultBranch string `json:"default_branch"`
}

func NewGitHubRepository() *GitHubRepository {
	return &GitHubRepository{
		host:  "github.com",
		token: os.Getenv("GITHUB_TOKEN"),
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

func getRepository(fullURL string) (IRepository, error) {
	hostUrl, err := getHost(fullURL)
	if err != nil {
		return nil, err
	}

	var repo IRepository
	switch hostUrl {
	case "github.com":
		repo = NewGitHubRepository()
	case "raw.githubusercontent.com":
		repo = NewGitHubRepository()
		repo.setIsFile(true)
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
	index := 0

	splittedRepo := strings.FieldsFunc(parsedURL.Path, func(c rune) bool { return c == '/' })
	if len(splittedRepo) < 2 {
		return fmt.Errorf("expecting <user>/<repo> in url path, received: '%s'", parsedURL.Path)
	}
	g.owner = splittedRepo[index]
	index += 1
	g.repo = splittedRepo[index]
	index += 1

	// root of repo
	if len(splittedRepo) < index+1 {
		return nil
	}

	// is file or dir
	switch splittedRepo[index] {
	case "blob":
		g.isFile = true
		index += 1
	case "tree":
		g.isFile = false
		index += 1
	}

	if len(splittedRepo) < index+1 {
		return nil
	}

	g.branch = splittedRepo[index]
	index += 1

	if len(splittedRepo) < index+1 {
		return nil
	}
	g.path = strings.Join(splittedRepo[index:], "/")

	return nil
}

func (g *GitHubRepository) getBranch() string     { return g.branch }
func (g *GitHubRepository) getTree() tree         { return g.tree }
func (g *GitHubRepository) setIsFile(isFile bool) { g.isFile = isFile }
func (g *GitHubRepository) getIsFile() bool       { return g.isFile }

func (g *GitHubRepository) setBranch(branchOptional string) error {
	// Checks whether the repository type is a master or another type.
	// By default it is "master", unless the branchOptional came with a value
	if branchOptional != "" {
		g.branch = branchOptional
	}
	if g.branch != "" {
		return nil
	}
	body, err := getter.HttpGetter(&http.Client{}, g.defaultBranchAPI(), g.getHeaders())
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
func (g *GitHubRepository) getHeaders() map[string]string {
	if g.token == "" {
		return nil
	}
	return map[string]string{"Authorization": fmt.Sprintf("token %s", g.token)}
}
func (g *GitHubRepository) setTree() error {
	if g.isFile {
		return nil
	}

	body, err := getter.HttpGetter(&http.Client{}, g.treeAPI(), g.getHeaders())
	if err != nil {
		return err
	}

	// press all tree to json
	var thisTree tree
	err = json.Unmarshal([]byte(body), &thisTree)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", g.treeAPI(), err.Error())
		// return nil
	}
	g.tree = thisTree

	return nil
}

func (g *GitHubRepository) treeAPI() string {
	return fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", joinOwnerNRepo(g.owner, g.repo), g.branch)
}

// return a list of yaml for a given repository tree
func (g *GitHubRepository) getFilesFromTree(filesExtensions []string) []string {
	var urls []string
	if g.isFile {
		if slices.Contains(filesExtensions, getFileExtension(g.path)) {
			return []string{fmt.Sprintf("%s/%s", g.rowYamlUrl(), g.path)}
		} else {
			return []string{}
		}
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
