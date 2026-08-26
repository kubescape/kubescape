package resourcehandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
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

// roundTripFunc lets a test supply a RoundTrip implementation inline.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestHttpGet_NonSuccessStatusReturnsError guards against a regression where
// httpGet returned the response body as-is regardless of the HTTP status
// code. An upstream error response (e.g. GitHub's 404/403/401 JSON error
// body) would previously be parsed as if it were a successful response,
// silently producing an empty/wrong result instead of a clear error.
func TestHttpGet_NonSuccessStatusReturnsError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		status     string
		body       string
	}{
		{name: "not found", statusCode: http.StatusNotFound, status: "404 Not Found", body: `{"message":"Not Found"}`},
		{name: "forbidden / rate limited", statusCode: http.StatusForbidden, status: "403 Forbidden", body: `{"message":"API rate limit exceeded"}`},
		{name: "unauthorized", statusCode: http.StatusUnauthorized, status: "401 Unauthorized", body: `{"message":"Bad credentials"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						Status:     tt.status,
						StatusCode: tt.statusCode,
						Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
						Header:     make(http.Header),
					}, nil
				}),
			}

			body, err := httpGet(client, "https://api.github.com/repos/owner/repo", nil)
			assert.Error(t, err)
			assert.Nil(t, body)
			assert.Contains(t, err.Error(), tt.status)
			assert.Contains(t, err.Error(), tt.body, tt.name+": error should surface the response body for diagnosis")
		})
	}
}

// TestHttpGet_NonSuccessStatusReturnsError_URLInError checks that the
// request URL, not just the status and body, appears in the returned error -
// the other half of the error contract, alongside truncation, that's easy to
// regress silently.
func TestHttpGet_NonSuccessStatusReturnsError_URLInError(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "404 Not Found",
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`{"message":"Not Found"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	const url = "https://api.github.com/repos/owner/repo"
	body, err := httpGet(client, url, nil)
	assert.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), url)
}

// TestHttpGet_NonSuccessStatusReturnsError_TruncatesLargeBody guards the
// 1024-byte cap on the error body: without it, an oversized upstream error
// response (or one that never closes) would grow the returned error
// unbounded.
func TestHttpGet_NonSuccessStatusReturnsError_TruncatesLargeBody(t *testing.T) {
	const maxBodyInError = 1024
	oversized := strings.Repeat("a", maxBodyInError*4) + "TAIL-SHOULD-BE-CUT"

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "500 Internal Server Error",
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString(oversized)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	body, err := httpGet(client, "https://api.github.com/repos/owner/repo", nil)
	assert.Error(t, err)
	assert.Nil(t, body)
	assert.NotContains(t, err.Error(), "TAIL-SHOULD-BE-CUT")
	assert.LessOrEqual(t, len(err.Error()), maxBodyInError+256, "error message should stay close to the 1024-byte body cap, not grow with the response size")
}

func TestHttpGet_SuccessReturnsBody(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "200 OK",
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"default_branch":"main"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	body, err := httpGet(client, "https://api.github.com/repos/owner/repo", nil)
	assert.NoError(t, err)
	assert.Equal(t, `{"default_branch":"main"}`, string(body))
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
