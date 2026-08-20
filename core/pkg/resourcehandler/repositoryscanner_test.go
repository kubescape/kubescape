package resourcehandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	urlA = "https://github.com/kubescape/kubescape"
	urlB = "https://github.com/kubescape/kubescape/blob/master/examples/online-boutique/adservice.yaml"
	urlC = "https://github.com/kubescape/kubescape/tree/master/examples/online-boutique"
	urlD = "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml"
)

var mockTree = tree{
	InnerTrees: []innerTree{
		{Path: "charts/fluent-bit/values.yaml"},
		{Path: "charts/fluent-bit/templates/configmap.yaml"},
		{Path: "charts/other-chart/templates/deployment.yaml"},
		{Path: "README.md"},
	},
}

type mockTransport struct{}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var responseBody []byte

	if req.URL.Host != "api.github.com" {
		return nil, fmt.Errorf("unexpected mocked host: %s", req.URL.Host)
	}

	if req.URL.Path == "/repos/kubescape/kubescape" {
		responseBody = []byte(`{"default_branch": "master"}`)
	} else if (req.URL.Path == "/repos/kubescape/kubescape/git/trees/master" || req.URL.Path == "/repos/kubescape/kubescape/git/trees/dev") && req.URL.RawQuery == "recursive=1" {
		tree := tree{
			InnerTrees: []innerTree{
				{Path: "examples/online-boutique/adservice.yaml"},
				{Path: "examples/online-boutique/cartservice.yaml"},
				{Path: "examples/online-boutique/checkoutservice.yaml"},
				{Path: "examples/online-boutique/currencyservice.yaml"},
				{Path: "examples/online-boutique/emailservice.yaml"},
				{Path: "examples/online-boutique/frontend.yaml"},
				{Path: "examples/online-boutique/loadgenerator.yaml"},
				{Path: "examples/online-boutique/paymentservice.yaml"},
				{Path: "examples/online-boutique/productcatalogservice.yaml"},
				{Path: "examples/online-boutique/recommendationservice.yaml"},
				{Path: "examples/online-boutique/redis.yaml"},
				{Path: "examples/online-boutique/shippingservice.yaml"},
				{Path: "README.md"},
			},
		}
		var marshalErr error
		responseBody, marshalErr = json.Marshal(tree)
		if marshalErr != nil {
			return nil, fmt.Errorf("mockTransport: failed to marshal tree: %w", marshalErr)
		}
	} else {
		return nil, fmt.Errorf("unexpected mocked request: %s", req.URL.Path)
	}

	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBuffer(responseBody)),
		Header:     make(http.Header),
	}, nil
}

func TestMain(m *testing.M) {
	originalTransport := defaultHTTPClient.Transport
	defaultHTTPClient.Transport = &mockTransport{}
	code := m.Run()
	defaultHTTPClient.Transport = originalTransport
	os.Exit(code)
}

func newMockGitHubRepository(path string, isFile bool) *GitHubRepository {
	return &GitHubRepository{
		host:   "github.com",
		owner:  "grafana",
		repo:   "helm-charts",
		branch: "main",
		path:   path,
		isFile: isFile,
		tree:   mockTree,
	}
}

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

func TestGetFilesFromTree(t *testing.T) {
	tests := []struct {
		name            string
		repo            *GitHubRepository
		extensions      []string
		expectedResults []string
	}{
		{
			name:       "Scan entire repo for YAML files",
			repo:       newMockGitHubRepository("", false),
			extensions: []string{"yaml", "yml"},
			expectedResults: []string{
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/fluent-bit/values.yaml",
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/fluent-bit/templates/configmap.yaml",
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/other-chart/templates/deployment.yaml",
			},
		},
		{
			name:       "Scan specific folder (fluent-bit) for YAML files",
			repo:       newMockGitHubRepository("charts/fluent-bit", false),
			extensions: []string{"yaml", "yml"},
			expectedResults: []string{
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/fluent-bit/values.yaml",
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/fluent-bit/templates/configmap.yaml",
			},
		},
		{
			name:            "Scan root with non-matching extension (JSON)",
			repo:            newMockGitHubRepository("", false),
			extensions:      []string{"json"},
			expectedResults: []string{},
		},
		{
			name:       "Scan specific file",
			repo:       newMockGitHubRepository("charts/fluent-bit/values.yaml", true),
			extensions: []string{"yaml"},
			expectedResults: []string{
				"https://raw.githubusercontent.com/grafana/helm-charts/main/charts/fluent-bit/values.yaml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.repo.getFilesFromTree(tt.extensions)

			if len(got) == 0 && len(tt.expectedResults) == 0 {
				return // both are empty, so this test case passes
			}

			if !reflect.DeepEqual(got, tt.expectedResults) {
				t.Errorf("getFilesFromTree() = %v, want %v", got, tt.expectedResults)
			}
		})
	}
}
