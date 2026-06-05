package vap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestDeployLibrary(t *testing.T) {
	t.Run("all downloads succeed with concatenation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Capture stdout
		content, err := deployLibrary(0)
		require.NoError(t, err)

		parts := strings.Split(content, "\n---\n")
		require.Len(t, parts, 3)
		assert.Equal(t, "policy-config-content", strings.TrimSpace(parts[0]))
		assert.Equal(t, "basic-control-content", strings.TrimSpace(parts[1]))
		assert.Contains(t, parts[2], "kubescape-policies-content")
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

		_, err := deployLibrary(0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
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

		_, err := deployLibrary(0)
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

		_, err := deployLibrary(0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})
}

func TestCreatePolicyBinding(t *testing.T) {
	t.Run("minimal binding with name and policy", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "", nil, nil)
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
		out, err := createPolicyBinding("my-binding", "c-0016", "Audit", "", []string{"ns1", "ns2"}, nil)
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
		out, err := createPolicyBinding("my-binding", "c-0016", "Warn", "", nil, []string{"app=nginx", "env=prod"})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx", "env": "prod"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
		assert.Equal(t, "Warn", string(binding.Spec.ValidationActions[0]))
	})

	t.Run("labels with whitespace are trimmed", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "", nil, []string{"app = nginx"})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
	})

	t.Run("with parameter reference", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "my-params", nil, nil)
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
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "my-params", []string{"ns1"}, []string{"app=nginx"})
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
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "", []string{}, nil)
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.NamespaceSelector)
	})

	t.Run("empty label slice does not add selector", func(t *testing.T) {
		out, err := createPolicyBinding("my-binding", "c-0016", "Deny", "", nil, []string{})
		require.NoError(t, err)

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err = yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.ObjectSelector)
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
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--control", "C-0012"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --parameter-reference")
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
	assert.Equal(t, "0s", timeoutFlag.DefValue)
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

	actionFlag := cmd.Flags().Lookup("action")
	require.NotNil(t, actionFlag)
	assert.Equal(t, "Deny", actionFlag.DefValue)

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
			name:      "control not present in released CEL library",
			controlID: "C-0013",
			wantErr:   "unsupported control ID",
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
	validLabels := []string{"app=nginx", "env1=prod2", "App=Value", "appName=NginxValue", "app-name=nginx", "app.name=nginx", "app_name=nginx", "app.kubernetes.io/name=nginx", "key=", "app = nginx"}
	invalidLabels := []string{"key value", "=value", "key=val=extra", "app@=nginx", "app=nginx@", "app!=nginx", "app", "app==nginx"}

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
			assert.True(t, strings.Contains(err.Error(), "invalid label selector") || strings.Contains(err.Error(), "only '=' equality"), "unexpected error: %v", err)
		})
	}
}

func TestCreatePolicyBindingCmdAllActions(t *testing.T) {
	validActions := []string{"Deny", "Audit", "Warn"}
	invalidActions := []string{"Allow", "deny", "audit", "warn", "", "Log", "Reject"}

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

	t.Run("timeout flag is registered with default 0s", func(t *testing.T) {
		timeoutFlag := cmd.Flags().Lookup("timeout")
		require.NotNil(t, timeoutFlag)
		assert.Equal(t, "0s", timeoutFlag.DefValue)
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
