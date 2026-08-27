package vap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func TestIsValidK8sObjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// valid names
		{name: "single lowercase letter", input: "a", wantErr: false},
		{name: "lowercase word", input: "abc", wantErr: false},
		{name: "alphanumeric with hyphen", input: "abc-def", wantErr: false},
		{name: "starts with digit", input: "123", wantErr: false},
		{name: "contains multiple hyphens", input: "abc-def-ghi", wantErr: false},
		{name: "hyphen in middle", input: "abc-def123", wantErr: false},
		{name: "dots in middle", input: "abc.def", wantErr: false},
		{name: "dots and hyphens mixed", input: "team.prod-v2", wantErr: false},
		{name: "exactly 253 chars", input: strings.Repeat("a", 253), wantErr: false},
		{name: "1 char", input: "x", wantErr: false},

		// invalid - length
		{name: "empty string", input: "", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "exceeds 253 chars", input: strings.Repeat("a", 254), wantErr: true, errMsg: "no more than 253"},

		// invalid - starts/ends with dot or hyphen
		{name: "starts with hyphen", input: "-abc", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "ends with hyphen", input: "abc-", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "starts with dot", input: ".abc", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "ends with dot", input: "abc.", wantErr: true, errMsg: "RFC 1123 subdomain"},

		// invalid - uppercase
		{name: "contains uppercase", input: "Abc", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "all uppercase", input: "ABC", wantErr: true, errMsg: "RFC 1123 subdomain"},

		// invalid - special characters
		{name: "contains underscore", input: "abc_def", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "contains space", input: "abc def", wantErr: true, errMsg: "RFC 1123 subdomain"},
		{name: "contains at sign", input: "a@b", wantErr: true, errMsg: "RFC 1123 subdomain"},

		// invalid - starts/ends with digit
		{name: "starts with hyphen and digit", input: "-123abc", wantErr: true, errMsg: "RFC 1123 subdomain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidK8sObjectName(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidNamespace(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{name: "valid simple", input: "default", wantErr: false},
		{name: "valid with hyphen", input: "kube-system", wantErr: false},
		{name: "valid starts with digit", input: "0default", wantErr: false},
		{name: "empty", input: "", wantErr: true, errMsg: "RFC 1123 label"},
		{name: "exceeds 63 chars", input: strings.Repeat("a", 64), wantErr: true, errMsg: "no more than 63"},
		{name: "contains dot", input: "team.prod", wantErr: true, errMsg: "must not contain dots"},
		{name: "contains uppercase", input: "Default", wantErr: true, errMsg: "RFC 1123 label"},
		{name: "starts with hyphen", input: "-default", wantErr: true, errMsg: "RFC 1123 label"},
		{name: "ends with hyphen", input: "default-", wantErr: true, errMsg: "RFC 1123 label"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidNamespace(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDownloadFileToString(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello world")
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL, 0)
		require.NoError(t, err)
		assert.Equal(t, "hello world", result)
	})

	t.Run("server returns 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := downloadFileToString(server.URL, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})

	t.Run("server returns 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := downloadFileToString(server.URL, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("connection refused", func(t *testing.T) {
		_, err := downloadFileToString("http://127.0.0.1:1/nonexistent", 0)
		require.Error(t, err)
	})

	t.Run("empty body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL, 0)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// redirectTransport redirects all HTTP requests to a local test server
type redirectTransport struct {
	originalTransport http.RoundTripper
	baseURL           string
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme = "http"
	u.Host = rt.baseURL
	req = req.Clone(req.Context())
	req.URL = &u
	req.Host = rt.baseURL
	if rt.originalTransport == nil {
		rt.originalTransport = http.DefaultTransport
	}
	return rt.originalTransport.RoundTrip(req)
}

func TestDeployLibraryServesEmbeddedBundleByDefault(t *testing.T) {
	// Any HTTP request would land on this failing server, so a pass proves the
	// default path never touches the network.
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{
		baseURL:           strings.TrimPrefix(server.URL, "http://"),
		originalTransport: server.Client().Transport,
	}
	defer func() { http.DefaultTransport = origTransport }()

	content, err := deployLibrary("", 0)
	require.NoError(t, err)
	assert.Zero(t, requests, "the embedded default must not touch the network")

	embedded, err := cel.EmbeddedLibraryYAML()
	require.NoError(t, err)
	assert.Equal(t, embedded, content, "deploy-library must serve the bundle embedded in the binary")
}

func TestDeployLibraryFromRelease(t *testing.T) {
	t.Run("all downloads succeed with concatenation", func(t *testing.T) {
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			switch {
			case strings.Contains(r.URL.Path, "policy-configuration-definition"):
				fmt.Fprint(w, "policy-config-content")
			case strings.Contains(r.URL.Path, "basic-control-configuration"):
				fmt.Fprint(w, "basic-control-content")
			case strings.Contains(r.URL.Path, "kubescape-validating-admission-policies"):
				fmt.Fprint(w, "kubescape-policies-content")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Redirect all HTTP traffic to our test server.
		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		content, err := deployLibrary("v0.11", 0)
		require.NoError(t, err)

		parts := strings.Split(content, "\n---\n")
		require.Len(t, parts, 3)
		assert.Equal(t, "policy-config-content", strings.TrimSpace(parts[0]))
		assert.Equal(t, "basic-control-content", strings.TrimSpace(parts[1]))
		assert.Contains(t, parts[2], "kubescape-policies-content")

		// The tag must be pinned in every URL: no releases/latest.
		require.Len(t, paths, 3)
		for _, path := range paths {
			assert.Contains(t, path, "/releases/download/v0.11/")
			assert.NotContains(t, path, "latest")
		}
	})

	t.Run("first download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "policy-configuration-definition") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		_, err := deployLibrary("v0.11", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
		assert.Contains(t, err.Error(), "policy-configuration-definition.yaml")
	})

	t.Run("second download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "basic-control-configuration") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		_, err := deployLibrary("v0.11", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})

	t.Run("third download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "kubescape-validating-admission-policies") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		_, err := deployLibrary("v0.11", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})
}

// A release tag is pasted straight into the release URL, so anything that can
// change the URL's shape has to be rejected before the request is built. Go's
// HTTP client forwards "../" segments verbatim and GitHub resolves them
// server-side, so a tag carrying them silently serves the admission policy
// library out of an unrelated repository - which deploy-library's own examples
// then pipe into "kubectl apply -f -".
func TestDeployLibraryRejectsTagsThatEscapeTheReleaseURL(t *testing.T) {
	malicious := []struct {
		name string
		tag  string
	}{
		{name: "parent directory traversal", tag: "../../../../attacker/evil-repo/releases/download/v1"},
		{name: "traversal after a real tag", tag: "v0.11/../../../../attacker/evil-repo/releases/download/v1"},
		{name: "plain path separator", tag: "attacker/evil-repo"},
		{name: "backslash separator", tag: `..\..\attacker`},
		{name: "query string truncates the path", tag: "v0.11?ref="},
		{name: "fragment truncates the path", tag: "v0.11#"},
		{name: "absolute url", tag: "https://attacker.example.com/x"},
	}
	// An empty tag is not in this table on purpose: it is how deployLibrary
	// selects the embedded bundle, so it never reaches the download path.

	const wantPrefix = "/kubescape/cel-admission-library/releases/download/"

	for _, tc := range malicious {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "attacker-controlled-content")
			}))
			defer server.Close()

			origTransport := http.DefaultTransport
			http.DefaultTransport = &redirectTransport{
				baseURL:           strings.TrimPrefix(server.URL, "http://"),
				originalTransport: server.Client().Transport,
			}
			defer func() { http.DefaultTransport = origTransport }()

			_, err := deployLibrary(tc.tag, 0)

			// The request must never be built at all: rejecting the tag up front
			// is what keeps the download pinned to the kubescape release.
			for _, path := range paths {
				assert.True(t, strings.HasPrefix(path, wantPrefix),
					"request escaped the pinned release URL: %q", path)
			}
			assert.Empty(t, paths, "an invalid release tag must not reach the network")
			require.Error(t, err, "an invalid release tag must be rejected")
			assert.Contains(t, err.Error(), "invalid release tag")
		})
	}
}

func TestValidateReleaseTag(t *testing.T) {
	valid := []string{"v0.11", "v0.0.1", "1.2.3", "v1.2.3-rc1", "v1.2.3+build.5", "release_2024", "v10"}
	for _, tag := range valid {
		t.Run("valid/"+tag, func(t *testing.T) {
			assert.NoError(t, validateReleaseTag(tag))
		})
	}

	invalid := []struct {
		name string
		tag  string
	}{
		{name: "empty", tag: ""},
		{name: "dot", tag: "."},
		{name: "dot dot", tag: ".."},
		{name: "leading dot", tag: ".v0.11"},
		{name: "leading hyphen", tag: "-v0.11"},
		{name: "forward slash", tag: "v0.11/x"},
		{name: "backslash", tag: `v0.11\x`},
		{name: "question mark", tag: "v0.11?x"},
		{name: "hash", tag: "v0.11#x"},
		{name: "percent encoded slash", tag: "v0.11%2F.."},
		{name: "space", tag: "v0.11 x"},
		{name: "at sign", tag: "v0.11@host"},
		{name: "colon", tag: "https:"},
		{name: "newline", tag: "v0.11\nx"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			err := validateReleaseTag(tc.tag)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid release tag")
		})
	}
}

func TestDeployLibraryAcceptsRealReleaseTags(t *testing.T) {
	// Tags the cel-admission-library actually publishes, plus the shapes
	// semver releases commonly take, must keep working.
	for _, tag := range []string{"v0.11", "v0.0.1", "1.2.3", "v1.2.3-rc1", "v1.2.3+build.5", "release_2024"} {
		t.Run(tag, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "content")
			}))
			defer server.Close()

			origTransport := http.DefaultTransport
			http.DefaultTransport = &redirectTransport{
				baseURL:           strings.TrimPrefix(server.URL, "http://"),
				originalTransport: server.Client().Transport,
			}
			defer func() { http.DefaultTransport = origTransport }()

			_, err := deployLibrary(tag, 0)
			require.NoError(t, err)
			require.Len(t, paths, len(libraryReleaseFiles))
			for _, path := range paths {
				assert.Equal(t, "/kubescape/cel-admission-library/releases/download/"+tag+"/", path[:strings.LastIndex(path, "/")+1])
			}
		})
	}
}

func TestCreatePolicyBinding(t *testing.T) {
	t.Run("minimal binding with name and policy", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, nil, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Equal(t, "admissionregistration.k8s.io/v1", binding.APIVersion)
		assert.Equal(t, "ValidatingAdmissionPolicyBinding", binding.Kind)
		assert.Equal(t, "my-binding", binding.Name)
		assert.Equal(t, "c-0016", binding.Spec.PolicyName)
		assert.Equal(t, []admissionv1.ValidationAction{admissionv1.Deny}, binding.Spec.ValidationActions)
		assert.Nil(t, binding.Spec.ParamRef)
		assert.Nil(t, binding.Spec.MatchResources.NamespaceSelector)
		assert.Nil(t, binding.Spec.MatchResources.ObjectSelector)
	})

	t.Run("with namespaces", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Audit}, "", []string{"ns1", "ns2"}, nil, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.NamespaceSelector)
		require.Len(t, binding.Spec.MatchResources.NamespaceSelector.MatchExpressions, 1)
		assert.Equal(t, "kubernetes.io/metadata.name", binding.Spec.MatchResources.NamespaceSelector.MatchExpressions[0].Key)
		assert.Equal(t, []string{"ns1", "ns2"}, binding.Spec.MatchResources.NamespaceSelector.MatchExpressions[0].Values)
		assert.Equal(t, "Audit", string(binding.Spec.ValidationActions[0]))
	})

	t.Run("with labels", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Warn}, "", nil, []string{"app=nginx", "env=prod"}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx", "env": "prod"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
		assert.Equal(t, "Warn", string(binding.Spec.ValidationActions[0]))
	})

	t.Run("labels with whitespace are trimmed", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, []string{"app = nginx"}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
	})

	t.Run("with parameter reference", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "my-params", nil, nil, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.ParamRef)
		assert.Equal(t, "my-params", binding.Spec.ParamRef.Name)
		assert.NotNil(t, binding.Spec.ParamRef.ParameterNotFoundAction)
		assert.Equal(t, admissionv1.DenyAction, *binding.Spec.ParamRef.ParameterNotFoundAction)
	})

	t.Run("all fields combined", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "my-params", []string{"ns1"}, []string{"app=nginx"}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Equal(t, "my-binding", binding.Name)
		assert.Equal(t, "c-0016", binding.Spec.PolicyName)
		assert.NotNil(t, binding.Spec.MatchResources.NamespaceSelector)
		assert.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.NotNil(t, binding.Spec.ParamRef)
	})

	t.Run("empty namespace slice does not add selector", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", []string{}, nil, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.NamespaceSelector)
	})

	t.Run("empty label slice does not add selector", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, []string{}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.ObjectSelector)
	})

	// No rules means the binding covers everything the policy matches, which is
	// what the apiserver does with an empty resourceRules.
	t.Run("empty resource rule slice does not add rules", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, nil, []string{})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Empty(t, binding.Spec.MatchResources.ResourceRules)
	})

	t.Run("with resource rules", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, nil, []string{"apps/v1/deployments", "/v1/pods"})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.Len(t, binding.Spec.MatchResources.ResourceRules, 2)

		apps := binding.Spec.MatchResources.ResourceRules[0]
		assert.Equal(t, []string{"apps"}, apps.APIGroups)
		assert.Equal(t, []string{"v1"}, apps.APIVersions)
		assert.Equal(t, []string{"deployments"}, apps.Resources)
		assert.Equal(t, []admissionv1.OperationType{admissionv1.OperationAll}, apps.Operations)

		core := binding.Spec.MatchResources.ResourceRules[1]
		assert.Equal(t, []string{""}, core.APIGroups)
		assert.Equal(t, []string{"pods"}, core.Resources)
	})

	t.Run("with custom resource rule", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, nil, []string{"agentsubstrate.google.com/v1/actortemplates"})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.Len(t, binding.Spec.MatchResources.ResourceRules, 1)
		assert.Equal(t, []string{"agentsubstrate.google.com"}, binding.Spec.MatchResources.ResourceRules[0].APIGroups)
		assert.Equal(t, []string{"actortemplates"}, binding.Spec.MatchResources.ResourceRules[0].Resources)
	})

	t.Run("invalid resource rule is rejected", func(t *testing.T) {
		_, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, nil, []string{"deployments"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected group/version/resource")
	})
}

func TestParseResourceRule(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			group    string
			version  string
			resource string
		}{
			{name: "grouped resource", input: "apps/v1/deployments", group: "apps", version: "v1", resource: "deployments"},
			{name: "core group", input: "/v1/pods", group: "", version: "v1", resource: "pods"},
			{name: "custom resource", input: "agentsubstrate.google.com/v1beta1/workerpools", group: "agentsubstrate.google.com", version: "v1beta1", resource: "workerpools"},
			{name: "subresource", input: "apps/v1/deployments/scale", group: "apps", version: "v1", resource: "deployments/scale"},
			{name: "wildcards", input: "*/*/*", group: "*", version: "*", resource: "*"},
			{name: "wildcard resource", input: "apps/v1/*", group: "apps", version: "v1", resource: "*"},
			{name: "surrounding whitespace", input: " apps / v1 / deployments ", group: "apps", version: "v1", resource: "deployments"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rule, err := parseResourceRule(tt.input)
				require.NoError(t, err)
				assert.Equal(t, []string{tt.group}, rule.APIGroups)
				assert.Equal(t, []string{tt.version}, rule.APIVersions)
				assert.Equal(t, []string{tt.resource}, rule.Resources)
				assert.Equal(t, []admissionv1.OperationType{admissionv1.OperationAll}, rule.Operations)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name   string
			input  string
			errMsg string
		}{
			{name: "empty", input: "", errMsg: "expected group/version/resource"},
			{name: "resource only", input: "deployments", errMsg: "expected group/version/resource"},
			{name: "group and version only", input: "apps/v1", errMsg: "expected group/version/resource"},
			{name: "missing version", input: "apps//deployments", errMsg: "version and resource are required"},
			{name: "missing resource", input: "apps/v1/", errMsg: "version and resource are required"},
			{name: "bad group", input: "App$/v1/deployments", errMsg: "invalid api group"},
			{name: "bad version", input: "apps/V1/deployments", errMsg: "invalid api version"},
			{name: "bad resource", input: "apps/v1/Deployments", errMsg: "invalid resource"},
			{name: "bad subresource", input: "apps/v1/deployments/Scale", errMsg: "invalid resource"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := parseResourceRule(tt.input)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			})
		}
	})
}

func TestCreatePolicyBindingCmdValidation(t *testing.T) {
	t.Run("all valid defaults", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("valid control ID resolves policy name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("lowercase control ID resolves policy name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "c-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("unsupported control ID", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-9999"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported control ID")
	})

	t.Run("resource rule is written to the binding", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--resource-rule", "apps/v1/deployments", "--output", outputFile})
		require.NoError(t, cmd.Execute())

		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal(content, &binding))
		require.Len(t, binding.Spec.MatchResources.ResourceRules, 1)
		assert.Equal(t, []string{"apps"}, binding.Spec.MatchResources.ResourceRules[0].APIGroups)
		assert.Equal(t, []string{"deployments"}, binding.Spec.MatchResources.ResourceRules[0].Resources)
	})

	t.Run("invalid resource rule fails the command", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--resource-rule", "deployments"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected group/version/resource")
	})

	t.Run("policy and control are mutually exclusive", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "kubescape-c-0016-allow-privilege-escalation", "--control", "C-0016"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one of --policy or --control")
	})

	t.Run("policy or control is required", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "either --policy or --control")
	})

	t.Run("invalid binding name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "INVALID-name", "--policy", "c-0016"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid policy binding name")
	})

	t.Run("invalid policy name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "_invalid"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid policy name")
	})

	t.Run("invalid namespace in slice", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--namespace", "valid", "--namespace", "_invalid"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid namespace")
	})

	t.Run("invalid action", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Allow"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid action")
	})

	t.Run("invalid parameter reference", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--parameter-reference", "_bad-ref"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid parameter reference")
	})

	t.Run("empty parameter reference is OK", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("known parameterized control requires parameter reference", func(t *testing.T) {
		// C-0009 declares a paramKind in the bundle but was missing from the
		// retired hand-typed params map, so this exact invocation used to emit
		// a broken binding silently.
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0009"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --parameter-reference")
	})

	t.Run("parameterized policy by name requires parameter reference", func(t *testing.T) {
		// The params check used to fire only on the --control path; --policy
		// could silently generate a broken binding for the same policy. Also
		// covers a cluster helper policy that no control lookup can reach.
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "cluster-policy-deny-insecure-capabilities"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --parameter-reference")
	})

	t.Run("policy name outside the bundle skips the params check", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "some-custom-policy"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("known parameterized control accepts parameter reference", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0001", "--parameter-reference", "basic-control-configuration"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("known non-parameterized control does not require parameter reference", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("non-parameterized control refuses a parameter reference", func(t *testing.T) {
		// C-0016 declares no paramKind, so the apiserver ignores the paramRef
		// and evaluates without params. This used to emit that binding silently,
		// leaving the caller believing the reference had configured the control.
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0016", "--parameter-reference", "basic-control-configuration"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "takes no --parameter-reference")
	})

	t.Run("non-parameterized policy by name refuses a parameter reference", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "kubescape-c-0016-allow-privilege-escalation", "--parameter-reference", "basic-control-configuration"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "takes no --parameter-reference")
	})

	t.Run("policy name outside the bundle accepts a parameter reference", func(t *testing.T) {
		// Neither direction of the check may fire on a policy we know nothing
		// about: its paramKind is unreadable, not absent.
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "some-custom-policy", "--parameter-reference", "my-params"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("params refusal names the shipped ControlConfiguration kind", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0009"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kubescape.io/v1 ControlConfiguration")
	})
}

func TestPolicyParamKind(t *testing.T) {
	t.Run("control resolves its paramKind and is always known", func(t *testing.T) {
		paramKind, known, err := policyParamKind("C-0009", "")
		require.NoError(t, err)
		assert.True(t, known)
		require.NotNil(t, paramKind)
		assert.Equal(t, "kubescape.io/v1", paramKind.APIVersion)
		assert.Equal(t, "ControlConfiguration", paramKind.Kind)
	})

	t.Run("non-parameterized control is known with no paramKind", func(t *testing.T) {
		paramKind, known, err := policyParamKind("C-0016", "")
		require.NoError(t, err)
		assert.True(t, known)
		assert.Nil(t, paramKind)
	})

	t.Run("control absent from the bundle errors instead of reading as unknown", func(t *testing.T) {
		_, known, err := policyParamKind("C-9999", "")
		require.Error(t, err)
		assert.False(t, known)
	})

	t.Run("policy outside the bundle is not known", func(t *testing.T) {
		paramKind, known, err := policyParamKind("", "some-custom-policy")
		require.NoError(t, err)
		assert.False(t, known)
		assert.Nil(t, paramKind)
	})
}

func TestGetDeployLibraryCmd(t *testing.T) {
	cmd := getDeployLibraryCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "deploy-library", cmd.Use)
	assert.Equal(t, "Install Kubescape CEL admission policy library", cmd.Short)
	assert.NotNil(t, cmd.RunE)

	// Check flags
	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	timeoutFlag := cmd.Flags().Lookup("timeout")
	require.NotNil(t, timeoutFlag)
	assert.Equal(t, "30s", timeoutFlag.DefValue)

	fromReleaseFlag := cmd.Flags().Lookup("from-release")
	require.NotNil(t, fromReleaseFlag)
	assert.Empty(t, fromReleaseFlag.DefValue, "embedded bundle must be the default")
}

func TestGetCreatePolicyBindingCmd(t *testing.T) {
	cmd := getCreatePolicyBindingCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "create-policy-binding", cmd.Use)
	assert.Equal(t, "Create a policy binding", cmd.Short)
	assert.NotNil(t, cmd.RunE)

	// Check that required flags are marked
	nameFlag := cmd.Flags().Lookup("name")
	require.NotNil(t, nameFlag)
	assert.Equal(t, "n", nameFlag.Shorthand)

	policyFlag := cmd.Flags().Lookup("policy")
	require.NotNil(t, policyFlag)
	assert.Equal(t, "p", policyFlag.Shorthand)

	controlFlag := cmd.Flags().Lookup("control")
	require.NotNil(t, controlFlag)
	assert.Equal(t, "c", controlFlag.Shorthand)

	namespaceFlag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, namespaceFlag)

	labelFlag := cmd.Flags().Lookup("label")
	require.NotNil(t, labelFlag)

	resourceRuleFlag := cmd.Flags().Lookup("resource-rule")
	require.NotNil(t, resourceRuleFlag)

	actionFlag := cmd.Flags().Lookup("action")
	require.NotNil(t, actionFlag)
	assert.Equal(t, "[Deny]", actionFlag.DefValue)

	paramRefFlag := cmd.Flags().Lookup("parameter-reference")
	require.NotNil(t, paramRefFlag)
	assert.Equal(t, "r", paramRefFlag.Shorthand)
}

func TestResolvePolicyName(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		controlID  string
		want       string
		wantErr    string
	}{
		{
			name:       "policy name is returned as-is",
			policyName: "kubescape-c-0016-allow-privilege-escalation",
			want:       "kubescape-c-0016-allow-privilege-escalation",
		},
		{
			name:      "control ID resolves to library policy",
			controlID: "C-0016",
			want:      "kubescape-c-0016-allow-privilege-escalation",
		},
		{
			name:      "lowercase control ID resolves",
			controlID: "c-0016",
			want:      "kubescape-c-0016-allow-privilege-escalation",
		},
		{
			name:    "neither policy nor control",
			wantErr: "either --policy or --control",
		},
		{
			name:       "both policy and control",
			policyName: "kubescape-c-0016-allow-privilege-escalation",
			controlID:  "C-0016",
			wantErr:    "only one of --policy or --control",
		},
		{
			name:      "unsupported control",
			controlID: "C-9999",
			wantErr:   "unsupported control ID",
		},
		{
			name:       "policy name is lowercased like control IDs are uppercased",
			policyName: "KUBESCAPE-C-0016-Allow-Privilege-Escalation",
			want:       "kubescape-c-0016-allow-privilege-escalation",
		},
		{
			// C-0012 used to ship as a policy with no controlId label, so
			// resolution by control ID failed even though the bundle carried the
			// policy. The library has since labelled it, and resolution matches
			// what deploy-library exposes by control ID, so it resolves now. The
			// unresolvable case is covered by "unsupported control" above.
			name:      "control labelled by the library resolves",
			controlID: "C-0012",
			want:      "kubescape-c-0012-deny-resources-with-sensitive-information-in-environment-variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePolicyName(tt.policyName, tt.controlID)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetVapHelperCmd(t *testing.T) {
	cmd := GetVapHelperCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "vap", cmd.Use)
	assert.Len(t, cmd.Commands(), 2)

	subCmdNames := []string{cmd.Commands()[0].Use, cmd.Commands()[1].Use}
	assert.Contains(t, subCmdNames, "deploy-library")
	assert.Contains(t, subCmdNames, "create-policy-binding")
}

func TestLabelSelectorRegexEdgeCases(t *testing.T) {
	// Regression for issue-3403: "==" is DoubleEquals, a distinct operator from
	// "=" (Equals) in k8s.io/apimachinery/pkg/selection, but both spellings mean
	// the same thing - a plain equality selector - and kubectl treats them
	// identically. "app==nginx" belongs in validLabels, not invalidLabels.
	validLabels := []string{"app=nginx", "env1=prod2", "App=Value", "appName=NginxValue", "app-name=nginx", "app.name=nginx", "app_name=nginx", "app.kubernetes.io/name=nginx", "key=", "app = nginx", "app==nginx"}
	invalidLabels := []string{"key value", "=value", "key=val=extra", "app@=nginx", "app=nginx@", "app!=nginx", "app"}

	for _, label := range validLabels {
		t.Run("valid label "+label, func(t *testing.T) {
			cmd := getCreatePolicyBindingCmd()
			cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", label})
			err := cmd.Execute()
			assert.NoError(t, err)
		})
	}

	for _, label := range invalidLabels {
		t.Run("invalid label "+label, func(t *testing.T) {
			cmd := getCreatePolicyBindingCmd()
			cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", label})
			err := cmd.Execute()
			require.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), "invalid label selector") || strings.Contains(err.Error(), "only equality label selectors"), "unexpected error: %v", err)
		})
	}
}

func TestCreatePolicyBindingCmdAllActions(t *testing.T) {
	validActions := []string{"Deny", "Audit", "Warn"}
	invalidActions := []string{"Allow", "deny", "audit", "warn", "Log", "Reject"}

	for _, action := range validActions {
		t.Run("valid action "+action, func(t *testing.T) {
			cmd := getCreatePolicyBindingCmd()
			cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", action})
			err := cmd.Execute()
			assert.NoError(t, err)
		})
	}

	for _, action := range invalidActions {
		t.Run("invalid action "+action, func(t *testing.T) {
			cmd := getCreatePolicyBindingCmd()
			cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", action})
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid action")
		})
	}

	// An empty value clears the slice rather than adding a blank action, so it
	// reports the missing action instead of an invalid one.
	t.Run("empty action clears the default", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", ""})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one --action is required")
	})
}

func TestParseValidationActions(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    []admissionv1.ValidationAction
		wantErr string
	}{
		{
			name:   "single action",
			values: []string{"Deny"},
			want:   []admissionv1.ValidationAction{admissionv1.Deny},
		},
		{
			name:   "audit and warn roll out together",
			values: []string{"Audit", "Warn"},
			want:   []admissionv1.ValidationAction{admissionv1.Audit, admissionv1.Warn},
		},
		{
			name:   "deny and audit are a valid pair",
			values: []string{"Deny", "Audit"},
			want:   []admissionv1.ValidationAction{admissionv1.Deny, admissionv1.Audit},
		},
		{
			name:   "order is preserved",
			values: []string{"Warn", "Audit"},
			want:   []admissionv1.ValidationAction{admissionv1.Warn, admissionv1.Audit},
		},
		{
			name:   "surrounding whitespace is trimmed",
			values: []string{" Audit ", "Warn"},
			want:   []admissionv1.ValidationAction{admissionv1.Audit, admissionv1.Warn},
		},
		{
			name:    "no action at all",
			values:  nil,
			wantErr: "at least one --action is required",
		},
		{
			name:    "unknown action",
			values:  []string{"Allow"},
			wantErr: "invalid action: Allow",
		},
		{
			name:    "lowercase is not the API spelling",
			values:  []string{"deny"},
			wantErr: "invalid action: deny",
		},
		{
			name:    "repeated action",
			values:  []string{"Audit", "Audit"},
			wantErr: "duplicate action: Audit",
		},
		{
			name:    "deny with warn is refused by the API",
			values:  []string{"Deny", "Warn"},
			wantErr: "actions Deny and Warn cannot be combined",
		},
		{
			name:    "deny with warn in either order",
			values:  []string{"Warn", "Deny"},
			wantErr: "actions Deny and Warn cannot be combined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValidationActions(tt.values)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreatePolicyBindingMultipleActions(t *testing.T) {
	out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Audit, admissionv1.Warn}, "", nil, nil, nil)
	require.NoError(t, err)

	var binding admissionv1.ValidatingAdmissionPolicyBinding
	require.NoError(t, yaml.Unmarshal([]byte(out), &binding))
	assert.Equal(t, []admissionv1.ValidationAction{admissionv1.Audit, admissionv1.Warn}, binding.Spec.ValidationActions)
}

func TestCreatePolicyBindingCmdMultipleActions(t *testing.T) {
	t.Run("repeated flag", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Audit", "--action", "Warn"})
		assert.NoError(t, cmd.Execute())
	})

	t.Run("comma separated", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Audit,Warn"})
		assert.NoError(t, cmd.Execute())
	})

	t.Run("deny with warn is rejected", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Deny,Warn"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be combined")
	})

	t.Run("duplicate is rejected", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Warn,Warn"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate action")
	})
}

func TestCreatePolicyBindingCmdRequiredFlags(t *testing.T) {
	cmd := getCreatePolicyBindingCmd()

	nameFlag := cmd.Flags().Lookup("name")
	require.NotNil(t, nameFlag)
	annotations := nameFlag.Annotations
	require.NotNil(t, annotations)
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "name flag should be marked as required")

	policyFlag := cmd.Flags().Lookup("policy")
	require.NotNil(t, policyFlag)
	assert.Nil(t, policyFlag.Annotations[cobra.BashCompOneRequiredFlag])

	controlFlag := cmd.Flags().Lookup("control")
	require.NotNil(t, controlFlag)
	assert.Nil(t, controlFlag.Annotations[cobra.BashCompOneRequiredFlag])
}

func TestDeployLibraryCmdTimeoutFlag(t *testing.T) {
	cmd := getDeployLibraryCmd()

	t.Run("timeout flag defaults to a bounded value", func(t *testing.T) {
		timeoutFlag := cmd.Flags().Lookup("timeout")
		require.NotNil(t, timeoutFlag)
		assert.Equal(t, "30s", timeoutFlag.DefValue)

		// The default must actually bound the request; a zero default would
		// leave http.Client unbounded and let a stalled download hang forever.
		got, err := cmd.Flags().GetDuration("timeout")
		require.NoError(t, err)
		assert.Equal(t, defaultDownloadTimeout, got)
		assert.NotZero(t, got)
	})

	t.Run("timeout can still be disabled explicitly", func(t *testing.T) {
		cmd := getDeployLibraryCmd()
		require.NoError(t, cmd.ParseFlags([]string{"--timeout", "0"}))
		got, err := cmd.Flags().GetDuration("timeout")
		require.NoError(t, err)
		assert.Zero(t, got, "--timeout 0 must remain the opt-out")
	})

	t.Run("timeout flag can be set via args", func(t *testing.T) {
		cmd := getDeployLibraryCmd()
		err := cmd.ParseFlags([]string{"--timeout", "30s"})
		require.NoError(t, err)
		got, err := cmd.Flags().GetDuration("timeout")
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, got)
	})

	t.Run("timeout flag accepts 0s shorthand", func(t *testing.T) {
		cmd := getDeployLibraryCmd()
		err := cmd.ParseFlags([]string{"--timeout", "0s"})
		require.NoError(t, err)
		got, err := cmd.Flags().GetDuration("timeout")
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), got)
	})
}

func TestDownloadFileToStringTimeout(t *testing.T) {
	t.Run("timeout 0 means no timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL, 0)
		require.NoError(t, err)
		assert.Equal(t, "ok", result)
	})

	t.Run("short timeout triggers on slow server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
				return
			}
			fmt.Fprint(w, "too late")
		}))
		defer server.Close()

		_, err := downloadFileToString(server.URL, 10*time.Millisecond)
		require.Error(t, err)
	})

	t.Run("non-zero timeout works for fast server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "fast")
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL, 5*time.Second)
		require.NoError(t, err)
		assert.Equal(t, "fast", result)
	})
}

// TestCheckResourceRulesInPolicyScope covers the refusal of a --resource-rule
// the bound policy can never match. The apiserver intersects the binding with
// the policy's matchConstraints, so such a rule yields a binding that applies
// cleanly and enforces nothing.
func TestCheckResourceRulesInPolicyScope(t *testing.T) {
	const c0016Policy = "kubescape-c-0016-allow-privilege-escalation"

	t.Run("rule outside the policy is refused", func(t *testing.T) {
		err := checkResourceRulesInPolicyScope([]string{"agents.x-k8s.io/v1beta1/sandboxes"}, "C-0016", c0016Policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "would match nothing")
		assert.Contains(t, err.Error(), "apps/v1/deployments", "the refusal names what the policy does match")
	})

	t.Run("rule inside the policy is accepted", func(t *testing.T) {
		require.NoError(t, checkResourceRulesInPolicyScope([]string{"apps/v1/deployments", "/v1/pods"}, "C-0016", c0016Policy))
	})

	t.Run("one out-of-scope rule refuses the whole binding", func(t *testing.T) {
		err := checkResourceRulesInPolicyScope([]string{"/v1/pods", "ate.dev/v1alpha1/actortemplates"}, "C-0016", c0016Policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ate.dev/v1alpha1/actortemplates")
	})

	t.Run("policy resolved by name only", func(t *testing.T) {
		err := checkResourceRulesInPolicyScope([]string{"ate.dev/v1alpha1/workerpools"}, "", c0016Policy)
		require.Error(t, err)
	})

	// Equivalent matching is the default and this command never sets matchPolicy,
	// so a rule the apiserver may convert into the policy is reported, not refused.
	t.Run("another version of a constrained resource is allowed", func(t *testing.T) {
		require.NoError(t, checkResourceRulesInPolicyScope([]string{"apps/v1beta1/deployments"}, "C-0016", c0016Policy))
		require.NoError(t, checkResourceRulesInPolicyScope([]string{"extensions/v1beta1/deployments"}, "C-0016", c0016Policy))
	})

	t.Run("policy outside the bundle is left unchecked", func(t *testing.T) {
		require.NoError(t, checkResourceRulesInPolicyScope([]string{"ate.dev/v1alpha1/workerpools"}, "", "my-own-sandbox-policy"))
	})

	t.Run("no rules is nothing to check", func(t *testing.T) {
		require.NoError(t, checkResourceRulesInPolicyScope(nil, "C-0016", c0016Policy))
	})

	// A subresource policy is a separate surface: binding it to the bare
	// resource would enforce nothing.
	t.Run("bare resource does not reach a subresource policy", func(t *testing.T) {
		err := checkResourceRulesInPolicyScope([]string{"/v1/pods"}, "", "cluster-policy-deny-exec")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/v1/pods/exec")

		require.NoError(t, checkResourceRulesInPolicyScope([]string{"/v1/pods/exec"}, "", "cluster-policy-deny-exec"))
	})
}

// TestClassifyResourceRule covers what the offline check can and cannot
// conclude. Only a resource mismatch is conclusive: matchResources defaults to
// matchPolicy Equivalent, so a group or version the policy does not name may
// still be an equivalent form of the same resource on the cluster.
func TestClassifyResourceRule(t *testing.T) {
	constraint := func(group, version, resource string) admissionv1.NamedRuleWithOperations {
		rule, err := parseResourceRule(strings.Join([]string{group, version, resource}, "/"))
		require.NoError(t, err)
		return rule
	}

	tests := []struct {
		name        string
		rule        string
		constraints []admissionv1.NamedRuleWithOperations
		want        resourceRuleScope
	}{
		{
			name:        "exact match",
			rule:        "agents.x-k8s.io/v1beta1/sandboxes",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("agents.x-k8s.io", "v1beta1", "sandboxes")},
			want:        ruleMatchesPolicy,
		},
		{
			name:        "another version of the same resource may be converted",
			rule:        "agents.x-k8s.io/v1alpha1/sandboxes",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("agents.x-k8s.io", "v1beta1", "sandboxes")},
			want:        ruleConvertsToPolicy,
		},
		{
			name:        "another group serving the same resource may be converted",
			rule:        "extensions/v1beta1/deployments",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("apps", "v1", "deployments")},
			want:        ruleConvertsToPolicy,
		},
		{
			name:        "a resource the policy never constrains",
			rule:        "agents.x-k8s.io/v1beta1/sandboxes",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("apps", "v1", "deployments")},
			want:        ruleOutsidePolicy,
		},
		{
			name:        "policy wildcard covers the rule",
			rule:        "agents.x-k8s.io/v1beta1/sandboxes",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")},
			want:        ruleMatchesPolicy,
		},
		{
			name:        "rule wildcard reaches one of the policy's groups",
			rule:        "*/v1/pods",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("", "v1", "pods")},
			want:        ruleMatchesPolicy,
		},
		{
			name:        "resource wildcard does not cover a subresource",
			rule:        "/v1/*",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("", "v1", "pods/exec")},
			want:        ruleOutsidePolicy,
		},
		{
			name:        "full wildcard covers a subresource",
			rule:        "/v1/*/*",
			constraints: []admissionv1.NamedRuleWithOperations{constraint("", "v1", "pods/exec")},
			want:        ruleMatchesPolicy,
		},
		{
			name: "matches the second of several policy rules",
			rule: "batch/v1/cronjobs",
			constraints: []admissionv1.NamedRuleWithOperations{
				constraint("", "v1", "pods"),
				constraint("batch", "v1", "cronjobs"),
			},
			want: ruleMatchesPolicy,
		},
		{
			name: "an exact match outranks a convertible one",
			rule: "apps/v1/deployments",
			constraints: []admissionv1.NamedRuleWithOperations{
				constraint("extensions", "v1beta1", "deployments"),
				constraint("apps", "v1", "deployments"),
			},
			want: ruleMatchesPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := parseResourceRule(tt.rule)
			require.NoError(t, err)
			assert.Equal(t, tt.want, classifyResourceRule(rule, tt.constraints))
		})
	}
}

func TestCreatePolicyBindingCmdResourceRuleScope(t *testing.T) {
	t.Run("out-of-scope rule fails the command", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0016", "--resource-rule", "agents.x-k8s.io/v1beta1/sandboxes"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "would match nothing")
	})

	t.Run("in-scope rule is written to the binding", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0016", "--resource-rule", "batch/v1/cronjobs", "--output", outputFile})
		require.NoError(t, cmd.Execute())

		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal(content, &binding))
		require.Len(t, binding.Spec.MatchResources.ResourceRules, 1)
		assert.Equal(t, []string{"cronjobs"}, binding.Spec.MatchResources.ResourceRules[0].Resources)
	})
}

// TestResourceSelectorReach covers what the command can conclude offline about
// one resource a policy constrains. The apiserver's namespace matcher returns
// "matched" for a cluster-scoped request before it parses the selector, so a
// namespaceSelector narrows only what this reports as narrowable.
func TestResourceSelectorReach(t *testing.T) {
	cluster, namespaced := admissionv1.ClusterScope, admissionv1.NamespacedScope

	tests := []struct {
		name     string
		scope    *admissionv1.ScopeType
		groups   []string
		resource string
		want     selectorReach
	}{
		{name: "built-in namespaced resource", groups: []string{""}, resource: "pods", want: reachNarrows},
		{name: "built-in cluster-scoped resource", groups: []string{"rbac.authorization.k8s.io"}, resource: "clusterroles", want: reachAlwaysMatches},
		{name: "built-in resource in another group is a different resource", groups: []string{"custom.io"}, resource: "roles", want: reachUnknown},
		{name: "wildcard group accepts the built-in answer", groups: []string{"*"}, resource: "clusterrolebindings", want: reachAlwaysMatches},

		// The one resource with no namespace of its own that the selector still
		// narrows: it is read against the Namespace's own labels.
		{name: "namespaces are narrowed by their own labels", groups: []string{""}, resource: "namespaces", want: reachNarrows},
		{name: "namespaces outrank a declared cluster scope", scope: &cluster, groups: []string{""}, resource: "namespaces", want: reachNarrows},
		{name: "namespaces in another group are not the core one", groups: []string{"custom.io"}, resource: "namespaces", want: reachUnknown},

		{name: "a declared scope answers for a custom resource", scope: &cluster, groups: []string{"agents.x-k8s.io"}, resource: "sandboxes", want: reachAlwaysMatches},
		{name: "a declared namespaced scope narrows a custom resource", scope: &namespaced, groups: []string{"ate.dev"}, resource: "workerpools", want: reachNarrows},
		{name: "an undeclared custom resource stays unknown", groups: []string{"agents.x-k8s.io"}, resource: "sandboxes", want: reachUnknown},

		{name: "a wildcard resource sweeps cluster-scoped ones", groups: []string{"*"}, resource: "*", want: reachAlwaysMatches},
		{name: "a subresource lives where its parent does", groups: []string{""}, resource: "pods/exec", want: reachNarrows},
		{name: "an empty resource concludes nothing", groups: []string{""}, resource: "", want: reachUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resourceSelectorReach(tt.scope, tt.groups, tt.resource))
		})
	}
}

// TestResourceScope pins the resource's own API scope, which is what a
// constraint's scope field is compared against. It reads a Namespace the way the
// apiserver's rules matcher does — cluster-scoped — where a namespaceSelector
// still narrows one by its own labels.
func TestResourceScope(t *testing.T) {
	cluster, namespaced := admissionv1.ClusterScope, admissionv1.NamespacedScope

	tests := []struct {
		name     string
		groups   []string
		resource string
		want     *admissionv1.ScopeType
	}{
		{name: "a built-in namespaced resource", groups: []string{""}, resource: "pods", want: &namespaced},
		{name: "a built-in cluster-scoped resource", groups: []string{"rbac.authorization.k8s.io"}, resource: "clusterroles", want: &cluster},
		{name: "a namespace is cluster-scoped to the rules matcher", groups: []string{""}, resource: "namespaces", want: &cluster},
		{name: "a subresource lives where its parent does", groups: []string{""}, resource: "pods/exec", want: &namespaced},
		{name: "a built-in plural in another group is another resource", groups: []string{"custom.io"}, resource: "roles", want: nil},
		{name: "a custom resource is not in the table", groups: []string{"agents.x-k8s.io"}, resource: "sandboxes", want: nil},
		{name: "a wildcard names no one resource", groups: []string{"*"}, resource: "*", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resourceScope(tt.groups, tt.resource))
		})
	}
}

// TestResolveNamespaceSelectorReach covers the surface the emitted binding
// actually carries: the policy's matchConstraints, less whatever the caller's
// own --resource-rule set drops.
func TestResolveNamespaceSelectorReach(t *testing.T) {
	constraint := func(group, version string, resources ...string) admissionv1.NamedRuleWithOperations {
		rule, err := parseResourceRule(strings.Join([]string{group, version, resources[0]}, "/"))
		require.NoError(t, err)
		rule.Resources = resources
		return rule
	}
	const rbac = "rbac.authorization.k8s.io"

	t.Run("a mixed policy is partly narrowable", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint(rbac, "v1", "rolebindings", "clusterrolebindings")}, nil)
		assert.Equal(t, []string{rbac + "/v1/clusterrolebindings"}, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	t.Run("a resource rule drops what it does not name", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{rbac + "/v1/rolebindings"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint(rbac, "v1", "rolebindings", "clusterrolebindings")}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	// The resource name is what a binding rule is compared on: matchPolicy
	// Equivalent may bridge a group or version, never one resource to another.
	t.Run("a resource rule at another version still keeps the resource", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{rbac + "/v1beta1/clusterrolebindings"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint(rbac, "v1", "rolebindings", "clusterrolebindings")}, bindingResourceRules(parsed))
		assert.Equal(t, []string{rbac + "/v1/clusterrolebindings"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	t.Run("a resource of unknown scope keeps the binding narrowable", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			constraint("agents.x-k8s.io", "v1beta1", "sandboxes"),
			constraint(rbac, "v1", "clusterroles"),
		}, nil)
		assert.Equal(t, []string{rbac + "/v1/clusterroles"}, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	t.Run("each group and version of a cluster-scoped resource is named once", func(t *testing.T) {
		rule := constraint(rbac, "v1", "clusterroles")
		rule.APIVersions = []string{"v1", "v1beta1"}

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{rule, rule}, nil)
		assert.Equal(t, []string{rbac + "/v1/clusterroles", rbac + "/v1beta1/clusterroles"}, reach.alwaysMatched)
	})

	// A wildcard constraint sweeps cluster-scoped resources only as far as the
	// binding lets it. What the selector has to reach is the intersection, so a
	// binding narrowed to a namespaced resource is narrowable however wide the
	// constraint reads on its own — reading the reach off "*" instead refuses a
	// binding that is exactly what --namespace is for.
	t.Run("a resource rule narrows a wildcard constraint", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"apps/v1/deployments"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	t.Run("a wildcard constraint narrowed to a cluster-scoped resource names it", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{rbac + "/v1/clusterroles"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")}, bindingResourceRules(parsed))
		assert.Equal(t, []string{rbac + "/v1/clusterroles"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	t.Run("only the rules covering a resource narrow it", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"apps/v1/deployments", rbac + "/v1/clusterroles"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")}, bindingResourceRules(parsed))
		assert.Equal(t, []string{rbac + "/v1/clusterroles"}, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	t.Run("an unnarrowed wildcard constraint keeps its whole reach", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")}, nil)
		assert.Equal(t, []string{"*/*/*"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	t.Run("a wildcard resource rule narrows nothing off a wildcard constraint", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"*/*/*"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*")}, bindingResourceRules(parsed))
		assert.Equal(t, []string{"*/*/*"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	t.Run("a subresource rule narrows a wildcard constraint to its parent's scope", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"/v1/pods/exec"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("*", "*", "*/*")}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	// Only a wildcard gives way: a rule at another group covers the resource the
	// constraint names, at the group the constraint names it at.
	t.Run("a named constraint group outranks the rule's", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"extensions/v1beta1/deployments"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{constraint("apps", "v1", "deployments")}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	// A constraint's scope field also decides what it does not cover: a rule
	// declaring one scope never matches a request of the other, so a resource on
	// the wrong side of it is outside the surface rather than part of it.
	scoped := func(scope admissionv1.ScopeType, rule admissionv1.NamedRuleWithOperations) admissionv1.NamedRuleWithOperations {
		rule.Scope = &scope
		return rule
	}

	t.Run("a declared cluster scope drops the namespaced resource beside it", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.ClusterScope, constraint(rbac, "v1", "rolebindings", "clusterrolebindings")),
		}, nil)
		assert.Equal(t, []string{rbac + "/v1/clusterrolebindings"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	// Refusing this named a namespaced resource as the cluster-scoped reason for
	// the refusal. The constraint matches no deployment at all, so the binding
	// covers nothing and there is nothing to report either way.
	t.Run("a declared cluster scope drops what a rule narrows a wildcard to", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{"apps/v1/deployments"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.ClusterScope, constraint("*", "*", "*")),
		}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	t.Run("a declared namespaced scope drops a cluster-scoped rule", func(t *testing.T) {
		parsed, err := parseResourceRules([]string{rbac + "/v1/clusterroles"})
		require.NoError(t, err)

		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.NamespacedScope, constraint("*", "*", "*")),
		}, bindingResourceRules(parsed))
		assert.Empty(t, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	// The table is contradicted only where it can speak. A declared scope stays
	// the answer for the custom resources it exists to answer for.
	t.Run("a declared scope still answers for a custom resource", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.ClusterScope, constraint("agents.x-k8s.io", "v1beta1", "sandboxes")),
		}, nil)
		assert.Equal(t, []string{"agents.x-k8s.io/v1beta1/sandboxes"}, reach.alwaysMatched)
		assert.False(t, reach.narrowable)
	})

	// The asymmetry, from the other side: a Namespace is cluster-scoped to the
	// rules matcher, so a cluster-scoped constraint covers it — and the selector
	// still narrows it by its own labels.
	t.Run("a declared cluster scope still covers narrowable namespaces", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.ClusterScope, constraint("", "v1", "namespaces")),
		}, nil)
		assert.Empty(t, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})

	t.Run("a scope of all scopes drops nothing", func(t *testing.T) {
		reach := resolveNamespaceSelectorReach([]admissionv1.NamedRuleWithOperations{
			scoped(admissionv1.AllScopes, constraint(rbac, "v1", "rolebindings", "clusterrolebindings")),
		}, nil)
		assert.Equal(t, []string{rbac + "/v1/clusterrolebindings"}, reach.alwaysMatched)
		assert.True(t, reach.narrowable)
	})
}

// TestCheckNamespaceSelectorScope covers --namespace against the policies the
// bundle actually ships. C-0225, C-0262 and C-0280 each constrain a namespaced
// resource alongside a cluster-scoped one, which the emitted namespaceSelector
// cannot narrow.
func TestCheckNamespaceSelectorScope(t *testing.T) {
	const (
		rbac        = "rbac.authorization.k8s.io"
		c0016Policy = "kubescape-c-0016-allow-privilege-escalation"
		c0280Policy = "kubescape-c-0280-deny-access-to-csr-approval-subresource"
	)

	t.Run("a fully namespaced policy is accepted", func(t *testing.T) {
		require.NoError(t, checkNamespaceSelectorScope([]string{"prod"}, nil, "C-0016", c0016Policy))
	})

	// Accepted, because the namespaced half of the binding is what was asked
	// for. What the warning names is pinned on the constraints themselves.
	t.Run("a mixed policy is accepted with a warning", func(t *testing.T) {
		for control, clusterScoped := range map[string]string{
			"C-0225": rbac + "/v1/clusterrolebindings",
			"C-0262": rbac + "/v1/clusterrolebindings",
			"C-0280": rbac + "/v1/clusterroles",
		} {
			constraints, err := policyMatchConstraints(control, "")
			require.NoError(t, err)
			require.NotNil(t, constraints)

			reach := resolveNamespaceSelectorReach(constraints.ResourceRules, nil)
			assert.Equal(t, []string{clusterScoped}, reach.alwaysMatched, control)
			assert.True(t, reach.narrowable, control)

			require.NoError(t, checkNamespaceSelectorScope([]string{"prod"}, nil, control, ""))
		}
	})

	// Narrowed to the cluster-scoped half, the selector has nothing left to act
	// on: the binding is exactly as broad as one carrying no --namespace.
	t.Run("a binding covering only cluster-scoped resources is refused", func(t *testing.T) {
		err := checkNamespaceSelectorScope([]string{"prod"}, []string{rbac + "/v1/clusterroles"}, "C-0280", c0280Policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "narrows nothing")
		assert.Contains(t, err.Error(), rbac+"/v1/clusterroles")
		assert.Contains(t, err.Error(), "control C-0280", "the refusal echoes the flag that was typed")
	})

	t.Run("narrowing to the namespaced half is accepted", func(t *testing.T) {
		require.NoError(t, checkNamespaceSelectorScope([]string{"prod"}, []string{rbac + "/v1/roles"}, "C-0280", c0280Policy))
	})

	t.Run("no namespace is nothing to check", func(t *testing.T) {
		require.NoError(t, checkNamespaceSelectorScope(nil, nil, "C-0280", c0280Policy))
	})

	t.Run("a policy outside the bundle is left unchecked", func(t *testing.T) {
		require.NoError(t, checkNamespaceSelectorScope([]string{"prod"}, nil, "", "my-own-sandbox-policy"))
	})

	t.Run("an unresolvable control is reported", func(t *testing.T) {
		require.Error(t, checkNamespaceSelectorScope([]string{"prod"}, nil, "C-9999", "kubescape-c-9999"))
	})
}

// TestCreatePolicyBindingCmdNamespaceScope covers the command end to end: a
// --namespace that narrows part of the policy still emits its binding, and one
// that narrows none of it fails before anything is written.
func TestCreatePolicyBindingCmdNamespaceScope(t *testing.T) {
	const rbac = "rbac.authorization.k8s.io"

	t.Run("a mixed policy still emits its binding", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0262", "--namespace", "prod", "--output", outputFile})
		require.NoError(t, cmd.Execute())

		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal(content, &binding))
		require.NotNil(t, binding.Spec.MatchResources.NamespaceSelector)
	})

	t.Run("a namespace narrowing nothing fails the command", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0280", "--namespace", "prod", "--resource-rule", rbac + "/v1/clusterroles", "--output", outputFile})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "narrows nothing")

		_, statErr := os.Stat(outputFile)
		assert.True(t, os.IsNotExist(statErr), "the binding must not be written")
	})
}

func TestParseObjectSelectorLabels(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		want   map[string]string
		errMsg string
	}{
		{name: "no labels", input: nil, want: map[string]string{}},
		{name: "single equality", input: []string{"app=nginx"}, want: map[string]string{"app": "nginx"}},
		{name: "double equals means the same thing", input: []string{"app==nginx"}, want: map[string]string{"app": "nginx"}},
		{name: "whitespace around the operator is trimmed", input: []string{"app = nginx"}, want: map[string]string{"app": "nginx"}},
		{name: "empty value is a real requirement", input: []string{"app="}, want: map[string]string{"app": ""}},
		{name: "several keys", input: []string{"app=nginx", "env=prod"}, want: map[string]string{"app": "nginx", "env": "prod"}},
		{name: "several requirements in one value", input: []string{"app=nginx,env=prod"}, want: map[string]string{"app": "nginx", "env": "prod"}},
		{name: "repeated key with the same value", input: []string{"app=nginx", "app=nginx"}, want: map[string]string{"app": "nginx"}},
		{name: "repeated key across operator spellings", input: []string{"app=nginx", "app==nginx"}, want: map[string]string{"app": "nginx"}},

		{name: "repeated key with conflicting values", input: []string{"app=nginx", "app=redis"}, errMsg: "conflicting values for label"},
		{name: "conflicting values in one value", input: []string{"app=nginx,app=redis"}, errMsg: "conflicting values for label"},
		{name: "trailing comma leaves a blank entry", input: []string{"app=nginx", ""}, want: map[string]string{"app": "nginx"}},
		{name: "leading comma leaves a blank entry", input: []string{"", "app=nginx"}, want: map[string]string{"app": "nginx"}},
		{name: "only a blank entry", input: []string{""}, errMsg: "selects nothing"},
		{name: "only whitespace", input: []string{"   "}, errMsg: "selects nothing"},
		{name: "only blank entries", input: []string{"", ""}, errMsg: "selects nothing"},
		{name: "set-based operator", input: []string{"app in (nginx)"}, errMsg: "only equality label selectors"},
		{name: "exists operator", input: []string{"app"}, errMsg: "only equality label selectors"},
		{name: "not-equal operator", input: []string{"app!=nginx"}, errMsg: "only equality label selectors"},
		{name: "unparsable selector", input: []string{"app=val=extra"}, errMsg: "invalid label selector"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseObjectSelectorLabels(tt.input)
			if tt.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreatePolicyBindingObjectSelector(t *testing.T) {
	// A conflicting pair used to collapse onto the last value, emitting a
	// binding that enforced the policy on a set the caller never asked for.
	t.Run("conflicting labels emit no binding", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, []string{"app=nginx", "app=redis"}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicting values for label")
		assert.Empty(t, out)
	})

	// Blank values used to emit an empty objectSelector, which matches every
	// object the policy matches rather than narrowing anything.
	t.Run("labels that select nothing emit no binding", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, []string{""}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "selects nothing")
		assert.Empty(t, out)
	})

	t.Run("repeated label with the same value binds once", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", []admissionv1.ValidationAction{admissionv1.Deny}, "", nil, []string{"app=nginx", "app=nginx"}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal([]byte(out), &binding))
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
	})
}

func TestCreatePolicyBindingCmdLabelSelector(t *testing.T) {
	t.Run("conflicting labels fail the command", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", "app=nginx", "--label", "app=redis"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicting values for label")
	})

	// The flag is comma-split, so a lone comma is how a caller reaches a slice
	// of nothing but blanks.
	t.Run("labels that select nothing fail the command", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", ","})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "selects nothing")
	})

	t.Run("a trailing comma still binds the labels given", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", "app=nginx,", "--output", outputFile})
		require.NoError(t, cmd.Execute())

		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal(content, &binding))
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
	})

	t.Run("labels are written to the binding", func(t *testing.T) {
		outputFile := filepath.Join(t.TempDir(), "binding.yaml")
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--label", "app=nginx", "--label", "env=prod", "--output", outputFile})
		require.NoError(t, cmd.Execute())

		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		require.NoError(t, yaml.Unmarshal(content, &binding))
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx", "env": "prod"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
	})
}
