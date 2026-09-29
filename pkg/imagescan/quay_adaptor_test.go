package imagescan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockQuayAPI struct {
	responses map[string][]byte
	errors    map[string]error
	calls     map[string]int
	mu        sync.Mutex
}

func newMockQuayAPI() *mockQuayAPI {
	return &mockQuayAPI{
		responses: make(map[string][]byte),
		errors:    make(map[string]error),
		calls:     make(map[string]int),
	}
}

func (m *mockQuayAPI) mockTag(org, repo, tag, digest string, isManifestList ...bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := fmt.Sprintf("/api/v1/repository/%s/%s/tag/?specificTag=%s&onlyActiveTags=true",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.QueryEscape(tag),
	)
	isList := false
	if len(isManifestList) > 0 {
		isList = isManifestList[0]
	}
	m.responses[path] = []byte(fmt.Sprintf(`{
		"tags": [
			{"name": "%s", "manifest_digest": "%s", "is_manifest_list": %t}
		]
	}`, tag, digest, isList))
}

func (m *mockQuayAPI) mockManifest(org, repo, digest string, isManifestList bool, manifestDataJSON string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.PathEscape(digest),
	)
	escapedData, _ := json.Marshal(manifestDataJSON)
	m.responses[path] = []byte(fmt.Sprintf(`{
		"digest": "%s",
		"is_manifest_list": %t,
		"manifest_data": %s
	}`, digest, isManifestList, string(escapedData)))
}

func (m *mockQuayAPI) DoRequest(_ context.Context, _ string, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls[path]++
	if err, ok := m.errors[path]; ok {
		return nil, err
	}

	// Enforce Quay's route constraint: security endpoints only accept manifest digests, not tags.
	if strings.Contains(path, "/manifest/") && strings.Contains(path, "/security") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "manifest" && i+1 < len(parts) {
				ref := parts[i+1]
				if !strings.HasPrefix(ref, "sha256:") {
					return nil, &quayStatusError{
						StatusCode: http.StatusNotFound,
						msg:        fmt.Sprintf("quay security route requires manifest digest, rejected tag %q (HTTP 404)", ref),
					}
				}
			}
		}
	}

	if resp, ok := m.responses[path]; ok {
		return resp, nil
	}
	return nil, &quayStatusError{
		StatusCode: http.StatusNotFound,
		msg:        fmt.Sprintf("mock url not found: %s", path),
	}
}

func (m *mockQuayAPI) DoRequestWithHeaders(ctx context.Context, method, path string, _ http.Header) ([]byte, http.Header, error) {
	bytes, err := m.DoRequest(ctx, method, path)
	if err != nil {
		return nil, nil, err
	}
	return bytes, nil, nil
}

func TestQuayAdaptor_DescribeAdaptor(t *testing.T) {
	adaptor := NewQuayAdaptor()
	assert.Equal(t, "Red Hat Quay Container Registry Vulnerability Adaptor", adaptor.DescribeAdaptor())
}

func TestQuayAdaptor_ExtractQuayRepo(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedOrg string
		expectedRep string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "standard org and repo",
			input:       "coreos/etcd",
			expectedOrg: "coreos",
			expectedRep: "etcd",
			wantErr:     false,
		},
		{
			name:        "with dashes dots and underscores",
			input:       "my-org.test/my_app-service.v1",
			expectedOrg: "my-org.test",
			expectedRep: "my_app-service.v1",
			wantErr:     false,
		},
		{
			name:        "leading and trailing slashes stripped",
			input:       "/myorg/myrepo/",
			expectedOrg: "myorg",
			expectedRep: "myrepo",
			wantErr:     false,
		},
		{
			name:        "uppercase converted to lowercase",
			input:       "MyOrg/MyRepo",
			expectedOrg: "myorg",
			expectedRep: "myrepo",
			wantErr:     false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
			errMsg:  "empty repository name",
		},
		{
			name:    "single component without org",
			input:   "ubuntu",
			wantErr: true,
			errMsg:  "expected organization/repository",
		},
		{
			name:        "three components accepted for nested repo",
			input:       "org/team/repo",
			wantErr:     false,
			expectedOrg: "org",
			expectedRep: "team/repo",
		},
		{
			name:        "four components accepted for deep nested repo",
			input:       "myorg/dept/team/service",
			wantErr:     false,
			expectedOrg: "myorg",
			expectedRep: "dept/team/service",
		},
		{
			name:    "path traversal 3-components rejected",
			input:   "../etc/passwd",
			wantErr: true,
			errMsg:  "invalid organization name",
		},
		{
			name:    "invalid characters in nested repo segment rejected",
			input:   "myorg/team/bad$repo",
			wantErr: true,
			errMsg:  "invalid repository name",
		},
		{
			name:    "path traversal characters rejected",
			input:   "../passwd",
			wantErr: true,
			errMsg:  "invalid organization name",
		},
		{
			name:    "path traversal in repo name rejected",
			input:   "myorg/..",
			wantErr: true,
			errMsg:  "invalid repository name",
		},
		{
			name:    "invalid characters in repo name",
			input:   "myorg/repo$bad",
			wantErr: true,
			errMsg:  "invalid repository name",
		},
		{
			name:    "leading dash in organization name rejected",
			input:   "-myorg/myrepo",
			wantErr: true,
			errMsg:  "invalid organization name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo, err := extractQuayRepo(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedOrg, org)
				assert.Equal(t, tt.expectedRep, repo)
			}
		})
	}
}

func TestQuayAdaptor_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/discovery" {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer bad-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Invalid Bearer token", "status": 401}`))
				return
			}
			if auth == "Basic "+base64.StdEncoding.EncodeToString([]byte("bad:bad")) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Bad credentials", "status": 401}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		registry    string
		credentials RegistryCredentials
		options     []QuayAdaptorOption
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid registry with bearer token",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "valid-token"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     false,
		},
		{
			name:        "valid registry with robot account basic auth",
			registry:    server.URL,
			credentials: RegistryCredentials{Username: "myorg+robot", Password: "robot-password"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     false,
		},
		{
			name:        "refuses credentials over plain http without opt-in",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "valid-token"},
			wantErr:     true,
			errMsg:      "refusing to send credentials over plain http",
		},
		{
			name:        "valid registry without credentials (public access)",
			registry:    server.URL,
			credentials: RegistryCredentials{},
			wantErr:     false,
		},
		{
			name:        "empty registry string",
			registry:    "",
			credentials: RegistryCredentials{},
			wantErr:     true,
			errMsg:      "registry host cannot be empty",
		},
		{
			name:        "invalid bearer token returns unauthorized",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "bad-token"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     true,
			errMsg:      "quay api error (401 ): Invalid Bearer token",
		},
		{
			name:        "invalid basic auth returns unauthorized",
			registry:    server.URL,
			credentials: RegistryCredentials{Username: "bad", Password: "bad"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     true,
			errMsg:      "quay api error (401 ): Bad credentials",
		},
		{
			name:        "connection refused to unreachable host",
			registry:    "http://127.0.0.1:0",
			credentials: RegistryCredentials{},
			wantErr:     true,
			errMsg:      "failed to connect to quay registry",
		},
		{
			name:        "rejects credentials when authority does not match registry host",
			registry:    server.URL,
			credentials: RegistryCredentials{Authority: "other-registry.com", Token: "valid-token"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     true,
			errMsg:      "credentials authority \"other-registry.com\" does not match registry host",
		},
		{
			name:        "accepts credentials when authority matches registry host",
			registry:    server.URL,
			credentials: RegistryCredentials{Authority: strings.TrimPrefix(server.URL, "http://"), Token: "valid-token"},
			options:     []QuayAdaptorOption{WithInsecureHTTPCredentials()},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewQuayAdaptor(tt.options...)
			err := adaptor.Login(context.Background(), tt.registry, tt.credentials)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("failed re-login invalidates previous authenticated session", func(t *testing.T) {
		adaptor := NewQuayAdaptor(WithInsecureHTTPCredentials())
		// 1. Initial successful login
		err := adaptor.Login(context.Background(), server.URL, RegistryCredentials{Token: "valid-token"})
		require.NoError(t, err)
		assert.NotNil(t, adaptor.client)

		// 2. Failed re-login with bad credentials
		err = adaptor.Login(context.Background(), server.URL, RegistryCredentials{Token: "bad-token"})
		require.Error(t, err)
		assert.Nil(t, adaptor.client, "client must be invalidated after failed re-login")
		assert.Empty(t, adaptor.registryHost, "registryHost must be cleared after failed re-login")

		// 3. Subsequent calls should fail because client is uninitialized
		_, scanErr := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "org/repo", Tag: "latest"},
		})
		require.Error(t, scanErr)
		assert.Contains(t, scanErr.Error(), "quay client not initialized")
	})
}

func TestQuayAdaptor_GetImagesScanStatus(t *testing.T) {
	adaptor := NewQuayAdaptor()

	t.Run("uninitialized client returns error", func(t *testing.T) {
		_, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay client not initialized")
	})

	mock := newMockQuayAPI()
	adaptor.client = mock

	t.Run("empty input returns empty output", func(t *testing.T) {
		res, err := adaptor.GetImagesScanStatus(context.Background(), nil)
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("missing both tag and hash returns zero status", func(t *testing.T) {
		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.False(t, res[0].IsScanAvailable)
		assert.False(t, res[0].IsBomAvailable)
		assert.True(t, res[0].LastScanDate.IsZero())
	})

	t.Run("invalid repository format returns error in aggregate", func(t *testing.T) {
		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "invalidrepo", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected organization/repository")
		require.Len(t, res, 1)
		assert.False(t, res[0].IsScanAvailable)
	})

	t.Run("scanned status marks scan available", func(t *testing.T) {
		digest := "sha256:etcd1234567890abcdef"
		mock.mockTag("coreos", "etcd", "v3.5.0", digest)
		path := quayManifestSecurityPath("coreos", "etcd", digest, false)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Name": "sha256:etcd1234567890abcdef"
				}
			}
		}`)

		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Tag: "v3.5.0"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.True(t, res[0].IsScanAvailable)
	})

	t.Run("queued status marks scan unavailable", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "app", "sha256:queued123", false)
		mock.responses[path] = []byte(`{"status": "queued", "data": null}`)

		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/app", Hash: "sha256:queued123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.False(t, res[0].IsScanAvailable)
	})

	t.Run("unsupported and failed statuses mark scan unavailable", func(t *testing.T) {
		path1 := quayManifestSecurityPath("myorg", "unsupported", "sha256:unsupported123", false)
		mock.responses[path1] = []byte(`{"status": "unsupported", "data": null}`)

		path2 := quayManifestSecurityPath("myorg", "failed", "sha256:failed123", false)
		mock.responses[path2] = []byte(`{"status": "failed", "data": null}`)

		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/unsupported", Hash: "sha256:unsupported123"},
			{Registry: "quay.io", Repository: "myorg/failed", Hash: "sha256:failed123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 2)
		assert.False(t, res[0].IsScanAvailable)
		assert.False(t, res[1].IsScanAvailable)
	})

	t.Run("api error propagates joined error while retaining result slot", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "error", "sha256:error123", false)
		mock.errors[path] = fmt.Errorf("connection reset by peer")

		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/error", Hash: "sha256:error123"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection reset by peer")
		require.Len(t, res, 1)
		assert.False(t, res[0].IsScanAvailable)
	})

	t.Run("malformed json returns error", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "badjson", "sha256:badjson123", false)
		mock.responses[path] = []byte(`{not-json`)

		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/badjson", Hash: "sha256:badjson123"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse scan status payload")
		require.Len(t, res, 1)
	})
}

func TestQuayAdaptor_GetImagesVulnerabilities(t *testing.T) {
	adaptor := NewQuayAdaptor()

	t.Run("uninitialized client returns error", func(t *testing.T) {
		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay client not initialized")
	})

	mock := newMockQuayAPI()
	adaptor.client = mock

	t.Run("empty input returns empty report slice", func(t *testing.T) {
		res, err := adaptor.GetImagesVulnerabilities(context.Background(), nil)
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("missing both tag and hash returns empty report", func(t *testing.T) {
		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Empty(t, res[0].Vulnerabilities)
	})

	t.Run("invalid repository format returns error", func(t *testing.T) {
		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "badrepo", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected organization/repository")
		require.Len(t, res, 1)
		assert.Empty(t, res[0].Vulnerabilities)
	})

	t.Run("clean scan with zero vulnerabilities", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "clean", "sha256:clean123", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": []
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/clean", Hash: "sha256:clean123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Empty(t, res[0].Vulnerabilities)
	})

	t.Run("completed scan with null layer returns empty report without error", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "nulllayer", "sha256:nulllayer123", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": null
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/nulllayer", Hash: "sha256:nulllayer123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Empty(t, res[0].Vulnerabilities)
	})

	t.Run("single vulnerability parsed accurately", func(t *testing.T) {
		path := quayManifestSecurityPath("coreos", "etcd", "sha256:d12345", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "openssl",
							"Version": "1.1.1n",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-0286",
									"Severity": "High",
									"Description": "Type confusion vulnerability in X.509 GeneralName.",
									"Link": "https://access.redhat.com/security/cve/CVE-2023-0286"
								}
							]
						}
					]
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Hash: "sha256:d12345"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)

		vuln := res[0].Vulnerabilities[0]
		assert.Equal(t, "CVE-2023-0286", vuln.ID)
		assert.Equal(t, "High", vuln.Severity)
		assert.Equal(t, "Type confusion vulnerability in X.509 GeneralName.", vuln.Description)
		assert.Equal(t, []string{"https://access.redhat.com/security/cve/CVE-2023-0286"}, vuln.Links)
	})

	t.Run("space-separated links split into multiple URLs", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "links", "sha256:links123", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "RHSA-2023:1234",
									"Severity": "High",
									"Link": "https://access.redhat.com/errata/RHSA-2023:1234 https://access.redhat.com/security/cve/CVE-2023-38545 https://bugzilla.redhat.com/123456"
								}
							]
						}
					]
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/links", Hash: "sha256:links123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)
		assert.Equal(t, []string{
			"https://access.redhat.com/errata/RHSA-2023:1234",
			"https://access.redhat.com/security/cve/CVE-2023-38545",
			"https://bugzilla.redhat.com/123456",
		}, res[0].Vulnerabilities[0].Links)
	})

	t.Run("deduplicates vulnerabilities across multiple packages and layers", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "multivuln", "sha256:multivuln123", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical",
									"Description": "SOCKS5 heap buffer overflow"
								},
								{
									"Name": "CVE-2023-38546",
									"Severity": "Low",
									"Description": "Cookie injection"
								}
							]
						},
						{
							"Name": "libcurl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical",
									"Description": "Duplicate report of SOCKS5 overflow"
								},
								{
									"Name": "CVE-2023-0001",
									"Severity": "Defcon1",
									"Description": "Catastrophic flaw"
								}
							]
						}
					]
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/multivuln", Hash: "sha256:multivuln123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)

		// 3 unique CVEs expected: CVE-2023-38545, CVE-2023-38546, CVE-2023-0001
		require.Len(t, res[0].Vulnerabilities, 3)

		vulnMap := make(map[string]Vulnerability)
		for _, v := range res[0].Vulnerabilities {
			vulnMap[v.ID] = v
		}

		assert.Contains(t, vulnMap, "CVE-2023-38545")
		assert.Equal(t, "Critical", vulnMap["CVE-2023-38545"].Severity)

		assert.Contains(t, vulnMap, "CVE-2023-38546")
		assert.Equal(t, "Low", vulnMap["CVE-2023-38546"].Severity)

		assert.Contains(t, vulnMap, "CVE-2023-0001")
		// Defcon1 normalized to Critical
		assert.Equal(t, "Critical", vulnMap["CVE-2023-0001"].Severity)
	})

	t.Run("deduplication retains highest severity when duplicate CVE has higher severity", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "multisev", "sha256:multisev123", true)
		mock.responses[path] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "distro-pkg",
							"Vulnerabilities": [
								{
									"Name": "CVE-2024-1111",
									"Severity": "Low",
									"Description": "Distro rating"
								}
							]
						},
						{
							"Name": "lang-pkg",
							"Vulnerabilities": [
								{
									"Name": "CVE-2024-1111",
									"Severity": "High",
									"Description": "Upstream rating"
								}
							]
						}
					]
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/multisev", Hash: "sha256:multisev123"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2024-1111", res[0].Vulnerabilities[0].ID)
		assert.Equal(t, "High", res[0].Vulnerabilities[0].Severity)
	})

	t.Run("severities normalized properly", func(t *testing.T) {
		severities := []struct {
			input    string
			expected string
		}{
			{"defcon1", "Critical"},
			{"Critical", "Critical"},
			{"high", "High"},
			{"Medium", "Medium"},
			{"low", "Low"},
			{"minimal", "Negligible"},
			{"informational", "Negligible"},
			{"untriaged", "Negligible"},
			{"unassigned", "Negligible"},
			{"none", "Negligible"},
			{"unknown", "Unknown"},
			{"unrecognized_severity_xyz", "Unknown"},
		}

		for _, s := range severities {
			assert.Equal(t, s.expected, normalizeQuaySeverity(s.input))
		}
	})

	t.Run("severity rank orders severities accurately", func(t *testing.T) {
		assert.Greater(t, quaySeverityRank("Critical"), quaySeverityRank("High"))
		assert.Greater(t, quaySeverityRank("High"), quaySeverityRank("Medium"))
		assert.Greater(t, quaySeverityRank("Medium"), quaySeverityRank("Low"))
		assert.Greater(t, quaySeverityRank("Low"), quaySeverityRank("Negligible"))
		assert.Greater(t, quaySeverityRank("Negligible"), quaySeverityRank("Unknown"))
	})

	t.Run("failed scan status returns error and retains report slot", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "failedscan", "sha256:failedscan123", true)
		mock.responses[path] = []byte(`{"status": "failed", "data": null}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/failedscan", Hash: "sha256:failedscan123"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay security scan failed for myorg/failedscan@sha256:failedscan123")
		require.Len(t, res, 1, "failed scan must retain report slot")
		assert.Equal(t, "myorg/failedscan", res[0].ImageID.Repository)
		assert.Empty(t, res[0].Vulnerabilities)
	})

	t.Run("queued and unsupported statuses return error and retain report slot", func(t *testing.T) {
		pathQueued := quayManifestSecurityPath("myorg", "queued", "sha256:queued123", true)
		mock.responses[pathQueued] = []byte(`{"status": "queued", "data": null}`)

		pathUnsupported := quayManifestSecurityPath("myorg", "unsupported", "sha256:unsupported123", true)
		mock.responses[pathUnsupported] = []byte(`{"status": "unsupported", "data": null}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/queued", Hash: "sha256:queued123"},
			{Registry: "quay.io", Repository: "myorg/unsupported", Hash: "sha256:unsupported123"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay security scan is queued")
		assert.Contains(t, err.Error(), "quay security scan unsupported")
		require.Len(t, res, 2, "both slots must be retained")
	})

	t.Run("failed-then-successful batch preserves order and aggregates error", func(t *testing.T) {
		path1 := quayManifestSecurityPath("myorg", "image1", "sha256:failed111", true)
		mock.responses[path1] = []byte(`{"status": "failed", "data": null}`)

		path2 := quayManifestSecurityPath("myorg", "image2", "sha256:success222", true)
		mock.responses[path2] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical"
								}
							]
						}
					]
				}
			}
		}`)

		images := []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/image1", Hash: "sha256:failed111"},
			{Registry: "quay.io", Repository: "myorg/image2", Hash: "sha256:success222"},
		}

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay security scan failed for myorg/image1@sha256:failed111")
		// Verify both results retained in input order
		require.Len(t, res, 2)
		assert.Equal(t, "myorg/image1", res[0].ImageID.Repository)
		assert.Empty(t, res[0].Vulnerabilities)
		assert.Equal(t, "myorg/image2", res[1].ImageID.Repository)
		require.Len(t, res[1].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-38545", res[1].Vulnerabilities[0].ID)
	})

	t.Run("api failure returns joined error with report placeholder", func(t *testing.T) {
		path := quayManifestSecurityPath("myorg", "fail", "sha256:fail123", true)
		mock.errors[path] = fmt.Errorf("gateway timeout 504")

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/fail", Hash: "sha256:fail123"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gateway timeout 504")
		require.Len(t, res, 1)
		assert.Empty(t, res[0].Vulnerabilities)
	})
}

func TestQuayAdaptor_GoldenFixtures(t *testing.T) {
	fixtureData, err := os.ReadFile("testdata/quay_fixtures.json")
	require.NoError(t, err)

	var fixtures map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fixtureData, &fixtures))

	mock := newMockQuayAPI()
	adaptor := NewQuayAdaptor()
	adaptor.client = mock

	mock.mockTag("coreos", "single", "latest", "sha256:single123")
	mock.mockTag("coreos", "multi", "latest", "sha256:multi123")

	// Mount single vuln fixture under digest
	singlePath := quayManifestSecurityPath("coreos", "single", "sha256:single123", true)
	mock.responses[singlePath] = fixtures["scanned_single_vuln"]

	singleStatusPath := quayManifestSecurityPath("coreos", "single", "sha256:single123", false)
	mock.responses[singleStatusPath] = fixtures["scanned_single_vuln"]

	// Mount multi vuln fixture under digest
	multiPath := quayManifestSecurityPath("coreos", "multi", "sha256:multi123", true)
	mock.responses[multiPath] = fixtures["scanned_multi_vuln"]

	multiStatusPath := quayManifestSecurityPath("coreos", "multi", "sha256:multi123", false)
	mock.responses[multiStatusPath] = fixtures["scanned_multi_vuln"]

	// 1. Check scan statuses from fixtures
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
		{Registry: "quay.io", Repository: "coreos/single", Tag: "latest"},
		{Registry: "quay.io", Repository: "coreos/multi", Tag: "latest"},
	})
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	assert.True(t, statuses[0].IsScanAvailable)
	assert.True(t, statuses[1].IsScanAvailable)

	// 2. Check vulnerability reports from fixtures
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "quay.io", Repository: "coreos/single", Tag: "latest"},
		{Registry: "quay.io", Repository: "coreos/multi", Tag: "latest"},
	})
	require.NoError(t, err)
	require.Len(t, reports, 2)

	// Single vuln
	require.Len(t, reports[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-0286", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "High", reports[0].Vulnerabilities[0].Severity)

	// Multi vuln: curl & libcurl with duplicate CVE-2023-38545, Defcon1 CVE-2023-0001, etc.
	require.Len(t, reports[1].Vulnerabilities, 5)
}

func TestQuayAdaptor_RateLimitingAndRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) <= 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message": "Rate limit exceeded", "status": 429}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "scanned", "data": null}`))
	}))
	defer server.Close()

	wrapper := &quayAPIWrapper{
		baseURL:         server.URL,
		httpClient:      server.Client(),
		maxResponseSize: maxRegistryAPIResponseBytes,
		maxRetries:      3,
		retryBackoff:    10 * time.Millisecond,
	}

	data, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/test-retry")
	require.NoError(t, err)
	assert.Contains(t, string(data), "scanned")
	assert.Equal(t, int32(3), attempts.Load())
}

func TestQuayAdaptor_RateLimitingExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message": "Rate limit permanently exceeded", "status": 429}`))
	}))
	defer server.Close()

	wrapper := &quayAPIWrapper{
		baseURL:         server.URL,
		httpClient:      server.Client(),
		maxResponseSize: maxRegistryAPIResponseBytes,
		maxRetries:      1,
		retryBackoff:    10 * time.Millisecond,
	}

	_, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/test-rate-limit")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quay api error (429 ): Rate limit permanently exceeded")
}

func TestQuayAdaptor_OversizedResponseRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("123456789012345"))
	}))
	defer server.Close()

	wrapper := &quayAPIWrapper{
		baseURL:         server.URL,
		httpClient:      server.Client(),
		maxResponseSize: 10, // Max 10 bytes
		maxRetries:      0,
	}

	_, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/oversized")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the 10-byte limit")
}

func TestQuayAdaptor_GetImagesInformation(t *testing.T) {
	adaptor := NewQuayAdaptor()

	t.Run("uninitialized client returns error", func(t *testing.T) {
		_, err := adaptor.GetImagesInformation(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay client not initialized")
	})

	mock := newMockQuayAPI()
	adaptor.client = mock

	t.Run("returns empty BOM structures", func(t *testing.T) {
		res, err := adaptor.GetImagesInformation(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "coreos/etcd", Tag: "latest"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Equal(t, "coreos/etcd", res[0].ImageID.Repository)
		assert.Empty(t, res[0].Bom)
	})
}

func TestQuayAdaptor_Destroy(t *testing.T) {
	adaptor := NewQuayAdaptor()
	mock := newMockQuayAPI()
	adaptor.client = mock

	require.NoError(t, adaptor.Destroy())
	assert.Nil(t, adaptor.client)

	// Destroy is safe to call repeatedly
	require.NoError(t, adaptor.Destroy())
}

func TestQuayAdaptor_Concurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/discovery" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "ok"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/tag/") {
			tag := r.URL.Query().Get("specificTag")
			if tag == "" {
				tag = "latest"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp, _ := json.Marshal(map[string]any{
				"tags": []map[string]string{
					{"name": tag, "manifest_digest": "sha256:d12345"},
				},
			})
			_, _ = w.Write(resp)
			return
		}
		if strings.Contains(r.URL.Path, "/manifest/") && strings.Contains(r.URL.Path, "/security") {
			parts := strings.Split(r.URL.Path, "/")
			for i, part := range parts {
				if part == "manifest" && i+1 < len(parts) {
					ref := parts[i+1]
					if !strings.HasPrefix(ref, "sha256:") {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message": "manifest not found"}`))
						return
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical"
								}
							]
						}
					]
				}
			}
		}`))
	}))
	defer server.Close()

	adaptor := NewQuayAdaptor()
	require.NoError(t, adaptor.Login(context.Background(), server.URL, RegistryCredentials{}))
	host := strings.TrimPrefix(server.URL, "http://")

	const numWorkers = 15
	const numIterations = 20

	var wg sync.WaitGroup
	wg.Add(numWorkers * 2)

	// Concurrently test GetImagesScanStatus
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				_, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
					{
						Registry:   host,
						Repository: fmt.Sprintf("org/repo%d", workerID),
						Tag:        fmt.Sprintf("v%d", j),
					},
				})
				assert.NoError(t, err)
			}
		}(i)
	}

	// Concurrently test GetImagesVulnerabilities
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
					{
						Registry:   host,
						Repository: fmt.Sprintf("org/repo%d", workerID),
						Tag:        fmt.Sprintf("v%d", j),
					},
				})
				assert.NoError(t, err)
				if !assert.Len(t, reports, 1) {
					continue
				}
				assert.Len(t, reports[0].Vulnerabilities, 1)
			}
		}(i)
	}

	wg.Wait()
}

func TestParseQuayTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{"RFC3339", "2023-10-15T12:30:00Z", false},
		{"RFC3339Nano", "2023-10-15T12:30:00.123456Z", false},
		{"RFC1123", "Sun, 15 Oct 2023 12:30:00 UTC", false},
		{"invalid format", "not-a-timestamp", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseQuayTimestamp(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.False(t, parsed.IsZero())
			}
		})
	}
}

func TestQuayAdaptor_FunctionalOptions(t *testing.T) {
	t.Run("default options are set properly", func(t *testing.T) {
		adaptor := NewQuayAdaptor()
		require.NotNil(t, adaptor)
		assert.Equal(t, defaultQuayTimeout, adaptor.config.Timeout)
		assert.Equal(t, defaultQuayMaxRetries, adaptor.config.MaxRetries)
		assert.Equal(t, defaultQuayRetryBackoff, adaptor.config.RetryBackoff)
		assert.Equal(t, int64(maxRegistryAPIResponseBytes), adaptor.config.MaxResponseSize)
		assert.Nil(t, adaptor.config.HTTPClient)
	})

	t.Run("custom options override defaults", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		adaptor := NewQuayAdaptor(
			WithHTTPClient(customClient),
			WithTimeout(30*time.Second),
			WithMaxRetries(5),
			WithRetryBackoff(250*time.Millisecond),
			WithMaxResponseSize(16*1024*1024),
		)
		require.NotNil(t, adaptor)
		assert.Equal(t, customClient, adaptor.config.HTTPClient)
		assert.Equal(t, 30*time.Second, adaptor.config.Timeout)
		assert.Equal(t, 5, adaptor.config.MaxRetries)
		assert.Equal(t, 250*time.Millisecond, adaptor.config.RetryBackoff)
		assert.Equal(t, int64(16*1024*1024), adaptor.config.MaxResponseSize)
	})

	t.Run("invalid or nil options safely handled", func(t *testing.T) {
		adaptor := NewQuayAdaptor(
			nil,
			WithHTTPClient(nil),
			WithTimeout(-5*time.Second),
			WithMaxRetries(-1),
			WithRetryBackoff(-1*time.Second),
			WithMaxResponseSize(-100),
		)
		require.NotNil(t, adaptor)
		assert.Equal(t, defaultQuayTimeout, adaptor.config.Timeout)
		assert.Equal(t, defaultQuayMaxRetries, adaptor.config.MaxRetries)
		assert.Equal(t, defaultQuayRetryBackoff, adaptor.config.RetryBackoff)
		assert.Equal(t, int64(maxRegistryAPIResponseBytes), adaptor.config.MaxResponseSize)
	})
}

func TestQuayAdaptor_RegistryHostPrefixStripping(t *testing.T) {
	tests := []struct {
		name         string
		registryHost string
		input        string
		expectedOrg  string
		expectedRep  string
		expectErr    bool
	}{
		{
			name:         "standard org and repo without host",
			registryHost: "custom.quay.enterprise:8443",
			input:        "myorg/myrepo",
			expectedOrg:  "myorg",
			expectedRep:  "myrepo",
			expectErr:    false,
		},
		{
			name:         "strips default quay.io prefix when registry host is default quay.io",
			registryHost: "quay.io",
			input:        "quay.io/myorg/myrepo",
			expectedOrg:  "myorg",
			expectedRep:  "myrepo",
			expectErr:    false,
		},
		{
			name:         "strips default quay.io prefix when registry host is empty",
			registryHost: "",
			input:        "quay.io/myorg/myrepo",
			expectedOrg:  "myorg",
			expectedRep:  "myrepo",
			expectErr:    false,
		},
		{
			name:         "strips configured custom registry host prefix",
			registryHost: "custom.quay.enterprise:8443",
			input:        "custom.quay.enterprise:8443/myorg/myrepo",
			expectedOrg:  "myorg",
			expectedRep:  "myrepo",
			expectErr:    false,
		},
		{
			name:         "strips leading slash with quay.io prefix when registry host is default",
			registryHost: "quay.io",
			input:        "/quay.io/myorg/myrepo/",
			expectedOrg:  "myorg",
			expectedRep:  "myrepo",
			expectErr:    false,
		},
		{
			name:         "quay.io prefix is rejected when custom registry host is configured",
			registryHost: "custom.quay.enterprise:8443",
			input:        "quay.io/myorg/myrepo",
			expectErr:    true,
		},
		{
			name:         "unknown registry host prefix results in invalid format error",
			registryHost: "custom.quay.enterprise:8443",
			input:        "other-registry.io/myorg/myrepo",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewQuayAdaptor()
			adaptor.registryHost = tt.registryHost
			org, repo, err := adaptor.extractRepo(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedOrg, org)
				assert.Equal(t, tt.expectedRep, repo)
			}
		})
	}
}

func TestQuayAdaptor_CheckScannerCapability(t *testing.T) {
	fixtures := loadTestFixtures(t)

	t.Run("scanner capability enabled", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = fixtures["discovery_enabled"]

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		enabled, err := adaptor.CheckScannerCapability(context.Background())
		require.NoError(t, err)
		assert.True(t, enabled)
	})

	t.Run("scanner capability disabled", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = fixtures["discovery_disabled"]

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		enabled, err := adaptor.CheckScannerCapability(context.Background())
		require.NoError(t, err)
		assert.False(t, enabled)
	})

	t.Run("uninitialized client returns error", func(t *testing.T) {
		adaptor := NewQuayAdaptor()
		_, err := adaptor.CheckScannerCapability(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "call Login first")
	})

	t.Run("network error returns error", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.errors["/api/v1/discovery"] = fmt.Errorf("connection timeout")

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		_, err := adaptor.CheckScannerCapability(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to query discovery endpoint")
	})

	t.Run("malformed json returns error", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = []byte("invalid-json")

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		_, err := adaptor.CheckScannerCapability(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse discovery response")
	})

	t.Run("swagger spec with security scanner route returns true", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = []byte(`{
			"swagger": "2.0",
			"paths": {
				"/api/v1/repository/{repository}/manifest/{manifestref}/security": {},
				"/api/v1/discovery": {}
			}
		}`)

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		enabled, err := adaptor.CheckScannerCapability(context.Background())
		require.NoError(t, err)
		assert.True(t, enabled)
	})

	t.Run("swagger spec without security scanner route returns false", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = []byte(`{
			"swagger": "2.0",
			"paths": {
				"/api/v1/repository/{repository}/tag": {},
				"/api/v1/discovery": {}
			}
		}`)

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		enabled, err := adaptor.CheckScannerCapability(context.Background())
		require.NoError(t, err)
		assert.False(t, enabled)
	})

	t.Run("discovery response without features or paths returns error", func(t *testing.T) {
		mock := newMockQuayAPI()
		mock.responses["/api/v1/discovery"] = []byte(`{"status": "ok"}`)

		adaptor := NewQuayAdaptor()
		adaptor.client = mock

		_, err := adaptor.CheckScannerCapability(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to determine security scanner capability")
	})
}

func TestQuayAdaptor_EnterpriseFixture_DeduplicationAndEnrichment(t *testing.T) {
	fixtures := loadTestFixtures(t)
	enterpriseFixture, ok := fixtures["enterprise_multirepo_scan"]
	require.True(t, ok, "enterprise_multirepo_scan fixture must exist")

	mock := newMockQuayAPI()
	digest := "sha256:enterprise1234567890abcdef"
	path := quayManifestSecurityPath("enterprise-org", "app-service", digest, true)
	mock.responses[path] = enterpriseFixture

	adaptor := NewQuayAdaptor()
	adaptor.client = mock

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{
			Registry:   "quay.io",
			Repository: "quay.io/enterprise-org/app-service",
			Hash:       digest,
		},
	})
	require.NoError(t, err)
	require.Len(t, reports, 1)

	report := reports[0]
	// Deduplication: CVE-2023-4911 is reported under both glibc and python3, but must only appear once
	// Total unique CVEs:
	// - CVE-2023-3817 (openssl)
	// - CVE-2023-3446 (openssl)
	// - CVE-2023-4911 (glibc & python3 -> deduplicated to 1)
	// - CVE-2023-38545 (curl)
	// - CVE-2023-38546 (curl)
	// - CVE-2022-37434 (zlib)
	// - CVE-2023-24329 (python3)
	// Total = 7 unique CVEs
	assert.Len(t, report.Vulnerabilities, 7)

	vulnMap := make(map[string]Vulnerability)
	for _, v := range report.Vulnerabilities {
		vulnMap[v.ID] = v
	}

	// 1. Defcon1 severity mapped to Critical
	v1, exists := vulnMap["CVE-2023-3817"]
	require.True(t, exists)
	assert.Equal(t, "Critical", v1.Severity)
	assert.Contains(t, v1.Description, "fixed in 1.1.1k-2.el8")

	// 2. Empty description enriched with package name and fixed version
	v2, exists := vulnMap["CVE-2022-37434"]
	require.True(t, exists)
	assert.Equal(t, "High", v2.Severity)
	assert.Contains(t, v2.Description, "package zlib")
	assert.Contains(t, v2.Description, "fixed in 1.2.11-18.el8")

	// 3. Empty link enriched with NVD default
	v3, exists := vulnMap["CVE-2023-38546"]
	require.True(t, exists)
	assert.Equal(t, "Low", v3.Severity)
	require.Len(t, v3.Links, 1)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2023-38546", v3.Links[0])

	// 4. Critical severity curl CVE
	v4, exists := vulnMap["CVE-2023-38545"]
	require.True(t, exists)
	assert.Equal(t, "Critical", v4.Severity)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2023-38545", v4.Links[0])
}

func TestQuayAdaptor_ServerErrorAndContextCancellation(t *testing.T) {
	t.Run("structured server error message parsed accurately", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{
				"status": 500,
				"error_type": "internal_error",
				"message": "database replica lag exceeded threshold"
			}`))
		}))
		defer server.Close()

		adaptor := NewQuayAdaptor(WithMaxRetries(0))
		err := adaptor.Login(context.Background(), server.URL, RegistryCredentials{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database replica lag exceeded threshold")
	})

	t.Run("context cancellation during request aborts immediately", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		adaptor := NewQuayAdaptor(WithTimeout(5 * time.Second))
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{})
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"))
	})

	t.Run("transient 503 response is retried and succeeds on subsequent attempt", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if attempts.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"message": "temporarily unavailable"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"features": {"SECURITY_SCANNER": true}}`))
		}))
		defer server.Close()

		adaptor := NewQuayAdaptor(
			WithMaxRetries(2),
			WithRetryBackoff(10*time.Millisecond),
		)
		err := adaptor.Login(context.Background(), server.URL, RegistryCredentials{})
		require.NoError(t, err)
		assert.Equal(t, int32(2), attempts.Load())
	})

	t.Run("persistent 503 response exhausts retries and preserves status error", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message": "backend unavailable"}`))
		}))
		defer server.Close()

		adaptor := NewQuayAdaptor(
			WithMaxRetries(2),
			WithRetryBackoff(10*time.Millisecond),
		)
		err := adaptor.Login(context.Background(), server.URL, RegistryCredentials{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "503")
		assert.Equal(t, int32(3), attempts.Load()) // 1 initial + 2 retries
	})
}

func TestParseRetryAfter(t *testing.T) {
	defaultBackoff := 500 * time.Millisecond

	t.Run("empty header uses default", func(t *testing.T) {
		assert.Equal(t, defaultBackoff, parseRetryAfter("", defaultBackoff))
	})

	t.Run("valid numeric seconds", func(t *testing.T) {
		assert.Equal(t, 10*time.Second, parseRetryAfter("10", defaultBackoff))
	})

	t.Run("numeric seconds capped at maxQuayRetryAfter", func(t *testing.T) {
		assert.Equal(t, maxQuayRetryAfter, parseRetryAfter("86400", defaultBackoff))
	})

	t.Run("valid future HTTP-date", func(t *testing.T) {
		future := time.Now().Add(15 * time.Second).UTC().Format(http.TimeFormat)
		res := parseRetryAfter(future, defaultBackoff)
		assert.True(t, res > 10*time.Second && res <= 16*time.Second)
	})

	t.Run("future HTTP-date exceeding maxQuayRetryAfter is capped", func(t *testing.T) {
		farFuture := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
		assert.Equal(t, maxQuayRetryAfter, parseRetryAfter(farFuture, defaultBackoff))
	})

	t.Run("past HTTP-date uses default", func(t *testing.T) {
		past := time.Now().Add(-10 * time.Minute).UTC().Format(http.TimeFormat)
		assert.Equal(t, defaultBackoff, parseRetryAfter(past, defaultBackoff))
	})

	t.Run("malformed header uses default", func(t *testing.T) {
		assert.Equal(t, defaultBackoff, parseRetryAfter("not-a-number-or-date", defaultBackoff))
	})
}

func TestQuayAdaptor_TimeoutWithCustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Custom client with Timeout == 0
	customClient := &http.Client{}
	adaptor := NewQuayAdaptor(
		WithHTTPClient(customClient),
		WithTimeout(50*time.Millisecond),
		WithMaxRetries(0),
	)

	err := adaptor.Login(context.Background(), server.URL, RegistryCredentials{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "Client.Timeout"))
}

func TestQuayAdaptor_TagResolution(t *testing.T) {
	mock := newMockQuayAPI()
	adaptor := NewQuayAdaptor()
	adaptor.client = mock

	digest := "sha256:resolved9876543210abcdef"
	mock.mockTag("myorg", "myrepo", "v1.2.3", digest)

	securityPath := quayManifestSecurityPath("myorg", "myrepo", digest, true)
	statusPath := quayManifestSecurityPath("myorg", "myrepo", digest, false)

	mock.responses[securityPath] = []byte(`{
		"status": "scanned",
		"data": {
			"Layer": {
				"Features": [
					{
						"Name": "bash",
						"Vulnerabilities": [
							{
								"Name": "CVE-2023-1234",
								"Severity": "High"
							}
						]
					}
				]
			}
		}
	}`)
	mock.responses[statusPath] = []byte(`{
		"status": "scanned",
		"data": {
			"Layer": {
				"Name": "sha256:direct1234567890abcdef"
			}
		}
	}`)

	t.Run("tag resolved to manifest digest in GetImagesScanStatus", func(t *testing.T) {
		res, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/myrepo", Tag: "v1.2.3"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.True(t, res[0].IsScanAvailable)
	})

	t.Run("tag resolved to manifest digest in GetImagesVulnerabilities", func(t *testing.T) {
		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/myrepo", Tag: "v1.2.3"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-1234", res[0].Vulnerabilities[0].ID)
	})

	t.Run("direct digest hash bypasses tag resolution", func(t *testing.T) {
		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/myrepo", Hash: digest},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)
	})

	t.Run("unknown tag returns error and retains report slot", func(t *testing.T) {
		emptyTagPath := fmt.Sprintf("/api/v1/repository/%s/%s/tag/?specificTag=%s&onlyActiveTags=true",
			url.PathEscape("myorg"), url.PathEscape("myrepo"), url.QueryEscape("unknown-tag"))
		mock.responses[emptyTagPath] = []byte(`{"tags": []}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/myrepo", Tag: "unknown-tag"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tag unknown-tag not found in myorg/myrepo")
		require.Len(t, res, 1, "must retain report slot")
		assert.Equal(t, "myorg/myrepo", res[0].ImageID.Repository)

		statusRes, statusErr := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/myrepo", Tag: "unknown-tag"},
		})
		require.Error(t, statusErr)
		assert.Contains(t, statusErr.Error(), "tag unknown-tag not found in myorg/myrepo")
		require.Len(t, statusRes, 1, "must retain status slot")
	})

	t.Run("nested repository paths supported in tag and security routes", func(t *testing.T) {
		nestedDigest := "sha256:nested9876543210fedcba"
		mock.mockTag("myorg", "team/app", "v2.0.0", nestedDigest)
		nestedSecPath := quayManifestSecurityPath("myorg", "team/app", nestedDigest, true)
		mock.responses[nestedSecPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical"
								}
							]
						}
					]
				}
			}
		}`)

		res, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/team/app", Tag: "v2.0.0"},
		})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Len(t, res[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-38545", res[0].Vulnerabilities[0].ID)
	})

	t.Run("tag pointing to multi-arch manifest list resolves to platform child manifest digest", func(t *testing.T) {
		listDigest := "sha256:manifestlist1234567890abcdef"
		childAmd64Digest := "sha256:childamd641234567890abcdef"
		childArm64Digest := "sha256:childarm641234567890abcdef"

		mock.mockTag("myorg", "multiarch", "latest", listDigest, true)

		manifestListJSON := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
			"manifests": [
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "arm64", "os": "linux"}
				},
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "amd64", "os": "linux"}
				}
			]
		}`, childArm64Digest, childAmd64Digest)

		mock.mockManifest("myorg", "multiarch", listDigest, true, manifestListJSON)

		childSecPath := quayManifestSecurityPath("myorg", "multiarch", childAmd64Digest, true)
		mock.responses[childSecPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "openssl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-0286",
									"Severity": "High"
								}
							]
						}
					]
				}
			}
		}`)

		childStatusPath := quayManifestSecurityPath("myorg", "multiarch", childAmd64Digest, false)
		mock.responses[childStatusPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Name": "sha256:childamd641234567890abcdef"
				}
			}
		}`)

		statusRes, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/multiarch", Tag: "latest"},
		})
		require.NoError(t, err)
		require.Len(t, statusRes, 1)
		assert.True(t, statusRes[0].IsScanAvailable)

		vulnRes, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/multiarch", Tag: "latest"},
		})
		require.NoError(t, err)
		require.Len(t, vulnRes, 1)
		require.Len(t, vulnRes[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-0286", vulnRes[0].Vulnerabilities[0].ID)
	})

	t.Run("tag pointing to manifest list without amd64 falls back to available linux child", func(t *testing.T) {
		listDigest := "sha256:armlist1234567890abcdef"
		childArm64Digest := "sha256:armonly1234567890abcdef"

		mock.mockTag("myorg", "armonly", "v1.0", listDigest, true)

		manifestListJSON := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
			"manifests": [
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "arm64", "os": "linux"}
				}
			]
		}`, childArm64Digest)

		mock.mockManifest("myorg", "armonly", listDigest, true, manifestListJSON)

		childSecPath := quayManifestSecurityPath("myorg", "armonly", childArm64Digest, true)
		mock.responses[childSecPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": []
				}
			}
		}`)

		vulnRes, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/armonly", Tag: "v1.0"},
		})
		require.NoError(t, err)
		require.Len(t, vulnRes, 1)
		assert.Empty(t, vulnRes[0].Vulnerabilities)
	})

	t.Run("tag-valued security path is rejected by route constraint", func(t *testing.T) {
		_, err := mock.DoRequest(context.Background(), http.MethodGet, "/api/v1/repository/myorg/myrepo/manifest/v1.2.3/security?vulnerabilities=true")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "quay security route requires manifest digest")
	})

	t.Run("multi-arch manifest list digest in Hash resolves to platform child manifest digest", func(t *testing.T) {
		listDigest := "sha256:hashlist1234567890abcdef"
		childAmd64Digest := "sha256:hashchildamd641234567890"

		manifestListJSON := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
			"manifests": [
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "sha256:hashchildarm641234567890",
					"platform": {"architecture": "arm64", "os": "linux"}
				},
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "amd64", "os": "linux"}
				}
			]
		}`, childAmd64Digest)

		mock.mockManifest("myorg", "hashmulti", listDigest, true, manifestListJSON)

		childSecPath := quayManifestSecurityPath("myorg", "hashmulti", childAmd64Digest, true)
		mock.responses[childSecPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "curl",
							"Vulnerabilities": [
								{
									"Name": "CVE-2023-38545",
									"Severity": "Critical"
								}
							]
						}
					]
				}
			}
		}`)

		childStatusPath := quayManifestSecurityPath("myorg", "hashmulti", childAmd64Digest, false)
		mock.responses[childStatusPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Name": "sha256:childamd641234567890abcdef"
				}
			}
		}`)

		// Quay's real behavior: parent list digest security endpoint returns unsupported
		parentSecPath := quayManifestSecurityPath("myorg", "hashmulti", listDigest, true)
		mock.responses[parentSecPath] = []byte(`{"status": "unsupported"}`)
		parentStatusPath := quayManifestSecurityPath("myorg", "hashmulti", listDigest, false)
		mock.responses[parentStatusPath] = []byte(`{"status": "unsupported"}`)

		statusRes, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/hashmulti", Hash: listDigest},
		})
		require.NoError(t, err)
		require.Len(t, statusRes, 1)
		assert.True(t, statusRes[0].IsScanAvailable)

		vulnRes, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/hashmulti", Hash: listDigest},
		})
		require.NoError(t, err)
		require.Len(t, vulnRes, 1)
		require.Len(t, vulnRes[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-38545", vulnRes[0].Vulnerabilities[0].ID)
	})

	t.Run("comparing tag with pinned index digest yields identical results through both public methods", func(t *testing.T) {
		listDigest := "sha256:comparelist1234567890abcdef"
		childAmd64Digest := "sha256:comparechildamd641234567890"

		mock.mockTag("myorg", "comparemulti", "latest", listDigest, true)

		manifestListJSON := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
			"manifests": [
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "amd64", "os": "linux"}
				}
			]
		}`, childAmd64Digest)

		mock.mockManifest("myorg", "comparemulti", listDigest, true, manifestListJSON)

		childSecPath := quayManifestSecurityPath("myorg", "comparemulti", childAmd64Digest, true)
		mock.responses[childSecPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": [
						{
							"Name": "bash",
							"Vulnerabilities": [
								{
									"Name": "CVE-2022-3715",
									"Severity": "High"
								}
							]
						}
					]
				}
			}
		}`)

		childStatusPath := quayManifestSecurityPath("myorg", "comparemulti", childAmd64Digest, false)
		mock.responses[childStatusPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Name": "sha256:childamd641234567890abcdef"
				}
			}
		}`)

		// Parent list digest returns unsupported in Quay
		mock.responses[quayManifestSecurityPath("myorg", "comparemulti", listDigest, true)] = []byte(`{"status": "unsupported"}`)
		mock.responses[quayManifestSecurityPath("myorg", "comparemulti", listDigest, false)] = []byte(`{"status": "unsupported"}`)

		// Scan status by tag vs pinned digest
		tagStatus, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/comparemulti", Tag: "latest"},
		})
		require.NoError(t, err)
		digestStatus, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/comparemulti", Hash: listDigest},
		})
		require.NoError(t, err)
		assert.Equal(t, tagStatus[0].IsScanAvailable, digestStatus[0].IsScanAvailable)
		assert.Equal(t, tagStatus[0].LastScanDate, digestStatus[0].LastScanDate)

		// Vulnerabilities by tag vs pinned digest
		tagVulns, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/comparemulti", Tag: "latest"},
		})
		require.NoError(t, err)
		digestVulns, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/comparemulti", Hash: listDigest},
		})
		require.NoError(t, err)
		assert.Equal(t, tagVulns[0].Vulnerabilities, digestVulns[0].Vulnerabilities)

		// Both Tag and Hash supplied: Hash has precedence
		bothVulns, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/comparemulti", Tag: "latest", Hash: listDigest},
		})
		require.NoError(t, err)
		assert.Equal(t, tagVulns[0].Vulnerabilities, bothVulns[0].Vulnerabilities)
	})

	t.Run("direct single-image digest works without manifest list lookup", func(t *testing.T) {
		singleDigest := "sha256:directsingle1234567890abcdef"
		secPath := quayManifestSecurityPath("myorg", "singlerepo", singleDigest, true)
		mock.responses[secPath] = []byte(`{
			"status": "scanned",
			"data": {
				"Layer": {
					"Features": []
				}
			}
		}`)
		vulnRes, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/singlerepo", Hash: singleDigest},
		})
		require.NoError(t, err)
		require.Len(t, vulnRes, 1)
		assert.Empty(t, vulnRes[0].Vulnerabilities)

		manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", url.PathEscape("myorg"), "singlerepo", url.PathEscape(singleDigest))
		assert.Equal(t, 0, mock.calls[manifestPath], "single-arch digest should not trigger upfront manifest list lookup")
		assert.Equal(t, 1, mock.calls[secPath], "security endpoint should be queried directly")
	})

	t.Run("manifest list metadata request failure surfaces operational error", func(t *testing.T) {
		listDigest := "sha256:failfetchlist1234567890"
		mock.mockTag("myorg", "failmeta", "latest", listDigest, true)
		mock.errors[fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", url.PathEscape("myorg"), "failmeta", url.PathEscape(listDigest))] = errors.New("network timeout")

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/failmeta", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve manifest metadata")
	})

	t.Run("manifest list decode failure surfaces error instead of suppressing", func(t *testing.T) {
		listDigest := "sha256:faildecodelist1234567890"
		mock.mockTag("myorg", "faildecode", "latest", listDigest, true)
		manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", url.PathEscape("myorg"), "faildecode", url.PathEscape(listDigest))
		mock.responses[manifestPath] = []byte(`{invalid-json`)

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/faildecode", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode manifest metadata")
	})

	t.Run("manifest list empty manifest data surfaces error instead of suppressing", func(t *testing.T) {
		listDigest := "sha256:emptydata1234567890"
		mock.mockTag("myorg", "emptydata", "latest", listDigest, true)
		manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", url.PathEscape("myorg"), "emptydata", url.PathEscape(listDigest))
		mock.responses[manifestPath] = []byte(`{"digest": "` + listDigest + `", "is_manifest_list": true, "manifest_data": ""}`)

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/emptydata", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contained empty manifest data")
	})

	t.Run("manifest list with no child manifests surfaces child-selection error", func(t *testing.T) {
		listDigest := "sha256:nochildren1234567890"
		mock.mockTag("myorg", "nochildren", "latest", listDigest, true)
		emptyListJSON := `{"schemaVersion": 2, "manifests": []}`
		mock.mockManifest("myorg", "nochildren", listDigest, true, emptyListJSON)

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/nochildren", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contains no child manifests")
	})

	t.Run("tag resolution error preserves both v2 manifest and v1 tag lookup errors", func(t *testing.T) {
		v2Path := "/v2/myorg/bothfail/manifests/mytag"
		v1Path := fmt.Sprintf("/api/v1/repository/%s/%s/tag/?specificTag=%s&onlyActiveTags=true",
			url.PathEscape("myorg"), url.PathEscape("bothfail"), url.QueryEscape("mytag"))

		mock.errors[v2Path] = errors.New("v2 connection refused")
		mock.errors[v1Path] = errors.New("v1 unauthorized robot token")

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/bothfail", Tag: "mytag"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve tag mytag for myorg/bothfail")
		assert.Contains(t, err.Error(), "registry manifest lookup: v2 connection refused")
		assert.Contains(t, err.Error(), "tag api lookup: v1 unauthorized robot token")
	})

	t.Run("manifest list fallback error preserves both v1 manifest and v2 manifest lookup errors", func(t *testing.T) {
		listDigest := "sha256:bothfaillist1234567890"
		mock.mockTag("myorg", "bothfaillist", "latest", listDigest, true)
		v1ManifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", url.PathEscape("myorg"), "bothfaillist", url.PathEscape(listDigest))
		v2ManifestPath := fmt.Sprintf("/v2/myorg/bothfaillist/manifests/%s", url.PathEscape(listDigest))

		mock.errors[v1ManifestPath] = errors.New("v1 manifest timeout")
		mock.errors[v2ManifestPath] = errors.New("v2 manifest 503 unavailable")

		_, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/bothfaillist", Tag: "latest"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve manifest metadata")
		assert.Contains(t, err.Error(), "manifest api lookup: v1 manifest timeout")
		assert.Contains(t, err.Error(), "registry manifest lookup: v2 manifest 503 unavailable")
	})
}

func TestQuayAdaptor_RobotAccountTagResolution_ChallengeFlow(t *testing.T) {
	const (
		testRobotUser    = "privateorg+testrobot"
		testRobotCode    = "mock-robot-code"
		testIssuedTicket = "mock-issued-challenge-ticket"
		testOAuthTicket  = "mock-oauth-bearer-ticket"
		privateTag       = "v1.0.0"
		privateDigest    = "sha256:d19e7bb4ae4ac183a704263d1b630cfa9a910e86cfabcdef0123456789abcdef"
	)

	manifestPayload := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": {
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"size": 1234,
			"digest": "sha256:cfg1234567890abcdef"
		},
		"layers": []
	}`)

	scanStatusJSON := []byte(`{
		"status": "scanned",
		"data": {
			"Layer": {
				"Name": "sha256:private1234567890abcdef"
			}
		}
	}`)

	vulnReportJSON := []byte(`{
		"status": "scanned",
		"data": {
			"Layer": {
				"Features": [
					{
						"Name": "openssl",
						"Version": "3.0.7",
						"Vulnerabilities": [
							{
								"Name": "CVE-2023-0286",
								"Severity": "High",
								"Description": "Vulnerability in openssl"
							}
						]
					}
				]
			}
		}
	}`)

	var serverURL string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		// 1. Discovery endpoint
		if r.URL.Path == "/api/v1/discovery" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "ok"}`))
			return
		}

		// 2. Registry v2 token auth endpoint (/v2/auth)
		if r.URL.Path == "/v2/auth" {
			expectedBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testRobotUser+":"+testRobotCode))
			if auth == expectedBasic {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"token": "%s"}`, testIssuedTicket)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "invalid robot credentials"}`))
			return
		}

		// 3. Registry v2 manifest lookup (/v2/privateorg/privaterepo/manifests/v1.0.0 or /v2/privateorg/privaterepo/manifests/<digest>)
		if strings.HasPrefix(r.URL.Path, "/v2/privateorg/privaterepo/manifests/") {
			expectedChallengeBearer := "Bearer " + testIssuedTicket
			expectedOAuthBearer := "Bearer " + testOAuthTicket
			if auth != expectedChallengeBearer && auth != expectedOAuthBearer {
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:privateorg/privaterepo:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}`))
				return
			}
			w.Header().Set("Docker-Content-Digest", privateDigest)
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manifestPayload)
			return
		}

		// 4. Quay REST API tag endpoint (/api/v1/repository/privateorg/privaterepo/tag/...)
		// Quay's tag endpoint does NOT enable Basic auth, rejecting robot Basic auth with 401
		if strings.HasPrefix(r.URL.Path, "/api/v1/repository/privateorg/privaterepo/tag/") {
			if strings.HasPrefix(auth, "Basic ") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Basic auth not supported for tag endpoint", "status": 401}`))
				return
			}
			if auth == "Bearer "+testOAuthTicket {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"tags": [{"name": "%s", "manifest_digest": "%s", "is_manifest_list": false}]}`, privateTag, privateDigest)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message": "Unauthorized", "status": 401}`))
			return
		}

		// 5. Quay API Security endpoint (/api/v1/repository/privateorg/privaterepo/manifest/<digest>/security)
		// Quay's security endpoint explicitly enables Basic auth (process_basic_auth_no_pass)
		// and OAuth bearer auth, but does NOT accept registry v2 challenge tokens.
		if strings.HasPrefix(r.URL.Path, fmt.Sprintf("/api/v1/repository/privateorg/privaterepo/manifest/%s/security", privateDigest)) {
			expectedBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testRobotUser+":"+testRobotCode))
			expectedOAuthBearer := "Bearer " + testOAuthTicket
			if auth != expectedBasic && auth != expectedOAuthBearer {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Unauthorized", "status": 401}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			if r.URL.Query().Get("vulnerabilities") == "true" {
				_, _ = w.Write(vulnReportJSON)
			} else {
				_, _ = w.Write(scanStatusJSON)
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	mu.Lock()
	serverURL = server.URL
	mu.Unlock()

	ctx := context.Background()

	t.Run("refuses robot credentials over plain http without opt-in", func(t *testing.T) {
		adaptor := NewQuayAdaptor()
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{
			Username: testRobotUser,
			Password: testRobotCode,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to send credentials over plain http")
	})

	t.Run("robot credentials resolve private tag through registry challenge flow", func(t *testing.T) {
		adaptor := NewQuayAdaptor(WithInsecureHTTPCredentials())
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{
			Username: testRobotUser,
			Password: testRobotCode,
		})
		require.NoError(t, err)

		tagID := []ContainerImageIdentifier{
			{Repository: "privateorg/privaterepo", Tag: privateTag},
		}

		status, err := adaptor.GetImagesScanStatus(ctx, tagID)
		require.NoError(t, err)
		require.Len(t, status, 1)
		assert.True(t, status[0].IsScanAvailable)

		vulns, err := adaptor.GetImagesVulnerabilities(ctx, tagID)
		require.NoError(t, err)
		require.Len(t, vulns, 1)
		require.Len(t, vulns[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-0286", vulns[0].Vulnerabilities[0].ID)
	})

	t.Run("robot credentials with direct digest input succeed", func(t *testing.T) {
		adaptor := NewQuayAdaptor(WithInsecureHTTPCredentials())
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{
			Username: testRobotUser,
			Password: testRobotCode,
		})
		require.NoError(t, err)

		digestID := []ContainerImageIdentifier{
			{Repository: "privateorg/privaterepo", Hash: privateDigest},
		}

		status, err := adaptor.GetImagesScanStatus(ctx, digestID)
		require.NoError(t, err)
		require.Len(t, status, 1)
		assert.True(t, status[0].IsScanAvailable)

		vulns, err := adaptor.GetImagesVulnerabilities(ctx, digestID)
		require.NoError(t, err)
		require.Len(t, vulns, 1)
		require.Len(t, vulns[0].Vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-0286", vulns[0].Vulnerabilities[0].ID)
	})

	t.Run("robot credentials produce identical results for tag and digest inputs", func(t *testing.T) {
		adaptor := NewQuayAdaptor(WithInsecureHTTPCredentials())
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{
			Username: testRobotUser,
			Password: testRobotCode,
		})
		require.NoError(t, err)

		tagID := []ContainerImageIdentifier{{Repository: "privateorg/privaterepo", Tag: privateTag}}
		digestID := []ContainerImageIdentifier{{Repository: "privateorg/privaterepo", Hash: privateDigest}}

		tagStatus, err := adaptor.GetImagesScanStatus(ctx, tagID)
		require.NoError(t, err)
		digestStatus, err := adaptor.GetImagesScanStatus(ctx, digestID)
		require.NoError(t, err)
		assert.Equal(t, tagStatus[0].IsScanAvailable, digestStatus[0].IsScanAvailable)
		assert.Equal(t, tagStatus[0].LastScanDate, digestStatus[0].LastScanDate)

		tagVulns, err := adaptor.GetImagesVulnerabilities(ctx, tagID)
		require.NoError(t, err)
		digestVulns, err := adaptor.GetImagesVulnerabilities(ctx, digestID)
		require.NoError(t, err)
		assert.Equal(t, tagVulns[0].Vulnerabilities, digestVulns[0].Vulnerabilities)
	})

	t.Run("bearer token authentication works for tag and digest inputs", func(t *testing.T) {
		adaptor := NewQuayAdaptor(WithInsecureHTTPCredentials())
		err := adaptor.Login(ctx, server.URL, RegistryCredentials{
			Token: testOAuthTicket,
		})
		require.NoError(t, err)

		tagID := []ContainerImageIdentifier{{Repository: "privateorg/privaterepo", Tag: privateTag}}
		digestID := []ContainerImageIdentifier{{Repository: "privateorg/privaterepo", Hash: privateDigest}}

		tagVulns, err := adaptor.GetImagesVulnerabilities(ctx, tagID)
		require.NoError(t, err)
		require.Len(t, tagVulns, 1)
		require.Len(t, tagVulns[0].Vulnerabilities, 1)

		digestVulns, err := adaptor.GetImagesVulnerabilities(ctx, digestID)
		require.NoError(t, err)
		require.Len(t, digestVulns, 1)
		require.Len(t, digestVulns[0].Vulnerabilities, 1)
		assert.Equal(t, tagVulns[0].Vulnerabilities, digestVulns[0].Vulnerabilities)
	})
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestQuayAdaptor_AuthRealm_SchemeDowngradeRejection(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects http realm when baseURL is https", func(t *testing.T) {
		w := &quayAPIWrapper{
			baseURL:    "https://quay.io",
			username:   "robot+test",
			password:   "secret",
			httpClient: http.DefaultClient,
		}
		_, err := w.fetchChallengeToken(ctx, "http://quay.io/v2/auth", "quay.io", "repository:org/repo:pull")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme downgrade from https")
		assert.Contains(t, err.Error(), "refusing auth realm")
	})

	t.Run("allows http realm when baseURL is http", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token": "mock-token"}`))
		}))
		defer server.Close()

		w := &quayAPIWrapper{
			baseURL:    server.URL,
			username:   "robot+test",
			password:   "secret",
			httpClient: server.Client(),
		}
		tok, err := w.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		require.NoError(t, err)
		assert.Equal(t, "mock-token", tok)
	})

	t.Run("allows https realm when baseURL is https", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token": "mock-tls-token"}`))
		}))
		defer server.Close()

		w := &quayAPIWrapper{
			baseURL:    server.URL,
			username:   "robot+test",
			password:   "secret",
			httpClient: server.Client(),
		}
		tok, err := w.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		require.NoError(t, err)
		assert.Equal(t, "mock-tls-token", tok)
	})

	t.Run("rejects realm when host does not match baseURL host", func(t *testing.T) {
		w := &quayAPIWrapper{
			baseURL:    "https://quay.example.com",
			username:   "robot+test",
			password:   "secret",
			httpClient: http.DefaultClient,
		}
		_, err := w.fetchChallengeToken(ctx, "https://attacker.com/v2/auth", "quay.io", "repository:org/repo:pull")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "realm host does not match registry host")
	})

	t.Run("sends bearer token instead of basic auth when token configured", func(t *testing.T) {
		var authHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token": "scoped-token"}`))
		}))
		defer server.Close()

		const dummyToken = "test-bearer-token"
		w := &quayAPIWrapper{
			baseURL:    server.URL,
			token:      dummyToken,
			username:   "should-not-be-sent",
			password:   "test-password",
			httpClient: server.Client(),
		}
		tok, err := w.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		require.NoError(t, err)
		assert.Equal(t, "scoped-token", tok)
		assert.Equal(t, "Bearer "+dummyToken, authHeader, "must send configured bearer token, not basic auth")
	})
}

func TestQuayAdaptor_AuthRealm_HTTPSToHTTPRedirectRejection(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects https to http same-host redirect with default client", func(t *testing.T) {
		server := httptest.NewTLSServer(nil)
		redirectTarget := "http://" + server.Listener.Addr().String() + "/v2/auth-insecure"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		})
		defer server.Close()

		w := &quayAPIWrapper{
			baseURL:    server.URL,
			username:   "robot+test",
			password:   "secret",
			httpClient: server.Client(),
		}

		_, err := w.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme downgrade from https")
	})

	t.Run("rejects https to http same-host redirect with caller-provided client", func(t *testing.T) {
		server := httptest.NewTLSServer(nil)
		redirectTarget := "http://" + server.Listener.Addr().String() + "/v2/auth-insecure"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		})
		defer server.Close()

		customClient := server.Client()
		adaptor := NewQuayAdaptor(WithHTTPClient(customClient))
		require.NotNil(t, adaptor)

		clientAPI := adaptor.clientFactory(server.URL, "robot+test", "secret", "")
		wrapper, ok := clientAPI.(*quayAPIWrapper)
		require.True(t, ok)

		_, err := wrapper.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme downgrade from https")
	})

	t.Run("allows https to http same-host redirect when WithInsecureHTTPCredentials is true", func(t *testing.T) {
		server := httptest.NewTLSServer(nil)
		redirectTarget := "http://" + server.Listener.Addr().String() + "/v2/auth-target"
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		})
		defer server.Close()

		adaptor := NewQuayAdaptor(
			WithHTTPClient(server.Client()),
			WithInsecureHTTPCredentials(),
		)
		clientAPI := adaptor.clientFactory(server.URL, "robot+test", "secret", "")
		wrapper, ok := clientAPI.(*quayAPIWrapper)
		require.True(t, ok)

		_, err := wrapper.fetchChallengeToken(ctx, server.URL+"/v2/auth", "quay.io", "repository:org/repo:pull")
		// The redirect itself is permitted by scheme policy, though connection to plain HTTP
		// on a TLS listener will fail at transport/TLS level, not scheme downgrade.
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "scheme downgrade from https")
		assert.NotContains(t, err.Error(), "insecure http redirect not allowed")
	})

	t.Run("createQuayHTTPClient CheckRedirect policy enforcement", func(t *testing.T) {
		insecureReq, err := http.NewRequest("GET", "http://quay.io/v2/auth", nil)
		require.NoError(t, err)
		httpsVia := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "quay.io"}}}

		// Secure client rejects downgrade
		secClient := createQuayHTTPClient(nil, false)
		err = secClient.CheckRedirect(insecureReq, httpsVia)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme downgrade from https")

		// Insecure client allows redirect
		insecClient := createQuayHTTPClient(nil, true)
		err = insecClient.CheckRedirect(insecureReq, httpsVia)
		require.NoError(t, err)
	})
}

func TestQuayAdaptor_DirectDigestManifestList_ErrorPropagation(t *testing.T) {
	ctx := context.Background()

	t.Run("child security lookup 503 error is propagated by both public methods", func(t *testing.T) {
		mock := newMockQuayAPI()
		adaptor := NewQuayAdaptor()
		adaptor.client = mock
		adaptor.registryHost = "quay.io"

		listDigest := "sha256:list5031234567890abcdef"
		childDigest := "sha256:child5031234567890abcdef"

		manifestListJSON := fmt.Sprintf(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
			"manifests": [
				{
					"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
					"size": 524,
					"digest": "%s",
					"platform": {"architecture": "amd64", "os": "linux"}
				}
			]
		}`, childDigest)

		mock.mockManifest("myorg", "errtest", listDigest, true, manifestListJSON)

		// Parent security endpoints return "unsupported" (typical for manifest list in Quay Clair)
		parentStatusPath := quayManifestSecurityPath("myorg", "errtest", listDigest, false)
		mock.responses[parentStatusPath] = []byte(`{"status": "unsupported"}`)
		parentSecPath := quayManifestSecurityPath("myorg", "errtest", listDigest, true)
		mock.responses[parentSecPath] = []byte(`{"status": "unsupported"}`)

		// Child security endpoints return 503 Service Unavailable
		childStatusPath := quayManifestSecurityPath("myorg", "errtest", childDigest, false)
		mock.errors[childStatusPath] = fmt.Errorf("quay api returned status 503 for %s", childStatusPath)
		childSecPath := quayManifestSecurityPath("myorg", "errtest", childDigest, true)
		mock.errors[childSecPath] = fmt.Errorf("quay api returned status 503 for %s", childSecPath)

		// 1. GetImagesScanStatus must return the wrapped 503 operational error rather than unavailable (false, nil)
		statusRes, statusErr := adaptor.GetImagesScanStatus(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, statusErr, "GetImagesScanStatus must return error when child lookup fails with 503")
		assert.Contains(t, statusErr.Error(), "503")
		require.Len(t, statusRes, 1)
		assert.False(t, statusRes[0].IsScanAvailable)

		// 2. GetImagesVulnerabilities must return the wrapped 503 error rather than generic "unsupported"
		vulnRes, vulnErr := adaptor.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, vulnErr, "GetImagesVulnerabilities must return error when child lookup fails with 503")
		assert.Contains(t, vulnErr.Error(), "503")
		assert.NotContains(t, vulnErr.Error(), "quay security scan unsupported")
		require.Len(t, vulnRes, 1)
		assert.Empty(t, vulnRes[0].Vulnerabilities)
	})

	t.Run("manifest metadata lookup operational failure is propagated by both public methods", func(t *testing.T) {
		mock := newMockQuayAPI()
		adaptor := NewQuayAdaptor()
		adaptor.client = mock
		adaptor.registryHost = "quay.io"

		// Digest intentionally contains "404" to verify that error classification
		// relies on typed HTTP status code rather than error string matching.
		listDigest := "sha256:list404metaerr1234567890abcdef"

		// Parent security endpoints return "unsupported"
		mock.responses[quayManifestSecurityPath("myorg", "errtest", listDigest, false)] = []byte(`{"status": "unsupported"}`)
		mock.responses[quayManifestSecurityPath("myorg", "errtest", listDigest, true)] = []byte(`{"status": "unsupported"}`)

		// Manifest metadata lookup returns 503 error
		manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", "myorg", "errtest", listDigest)
		mock.errors[manifestPath] = &quayStatusError{StatusCode: http.StatusServiceUnavailable, msg: fmt.Sprintf("quay api returned status 503 for %s", manifestPath)}
		v2Path := fmt.Sprintf("/v2/%s/manifests/%s", "myorg/errtest", listDigest)
		mock.errors[v2Path] = &quayStatusError{StatusCode: http.StatusServiceUnavailable, msg: fmt.Sprintf("quay api returned status 503 for %s", v2Path)}

		// Both methods must surface the metadata retrieval error
		statusRes, statusErr := adaptor.GetImagesScanStatus(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, statusErr)
		assert.Contains(t, statusErr.Error(), "503")
		require.Len(t, statusRes, 1)
		assert.False(t, statusRes[0].IsScanAvailable)

		vulnRes, vulnErr := adaptor.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, vulnErr)
		assert.Contains(t, vulnErr.Error(), "503")
		require.Len(t, vulnRes, 1)
		assert.Empty(t, vulnRes[0].Vulnerabilities)
	})

	t.Run("isQuayNotFoundError classifies only HTTP 404 and does not false-positive on 404 in path or digest", func(t *testing.T) {
		// Non-404 error with "404" in path/digest string
		err503 := &quayStatusError{
			StatusCode: http.StatusServiceUnavailable,
			msg:        "quay api returned status 503 for /api/v1/repository/myorg/repo/manifest/sha256:abcd404ef123",
		}
		assert.False(t, isQuayNotFoundError(err503))

		// Generic error with "404" in text
		genericErr := fmt.Errorf("connection failed on port 4040")
		assert.False(t, isQuayNotFoundError(genericErr))

		// Typed 404 error
		err404 := &quayStatusError{
			StatusCode: http.StatusNotFound,
			msg:        "quay api returned status 404 for /api/v1/repository/myorg/repo/manifest/sha256:111",
		}
		assert.True(t, isQuayNotFoundError(err404))

		// Wrapped typed 404 error
		wrapped404 := fmt.Errorf("lookup failed: %w", err404)
		assert.True(t, isQuayNotFoundError(wrapped404))

		// Nil error
		assert.False(t, isQuayNotFoundError(nil))
	})

	t.Run("manifest metadata decode error is propagated by both public methods", func(t *testing.T) {
		mock := newMockQuayAPI()
		adaptor := NewQuayAdaptor()
		adaptor.client = mock
		adaptor.registryHost = "quay.io"

		listDigest := "sha256:listdecodeerr1234567890abcdef"

		// Parent security endpoints return "unsupported"
		mock.responses[quayManifestSecurityPath("myorg", "errtest", listDigest, false)] = []byte(`{"status": "unsupported"}`)
		mock.responses[quayManifestSecurityPath("myorg", "errtest", listDigest, true)] = []byte(`{"status": "unsupported"}`)

		// Manifest metadata returns corrupt JSON
		manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s", "myorg", "errtest", listDigest)
		mock.responses[manifestPath] = []byte(`{not valid json}`)

		statusRes, statusErr := adaptor.GetImagesScanStatus(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, statusErr)
		assert.Contains(t, statusErr.Error(), "failed to decode manifest metadata")
		require.Len(t, statusRes, 1)
		assert.False(t, statusRes[0].IsScanAvailable)

		vulnRes, vulnErr := adaptor.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{
			{Registry: "quay.io", Repository: "myorg/errtest", Hash: listDigest},
		})
		require.Error(t, vulnErr)
		assert.Contains(t, vulnErr.Error(), "failed to decode manifest metadata")
		require.Len(t, vulnRes, 1)
		assert.Empty(t, vulnRes[0].Vulnerabilities)
	})
}

func TestQuayAdaptor_ChallengeRetryFailure_PreservesOriginalResponseBody(t *testing.T) {
	ctx := context.Background()

	reqCount := 0
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			reqCount++
			switch reqCount {
			case 1:
				// Initial request returns 401 with challenge header and JSON body
				res := &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
				}
				res.Header.Set("WWW-Authenticate", `Bearer realm="http://example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
				return res, nil
			case 2:
				// Challenge token fetch succeeds
				res := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"token": "valid-token"}`)),
				}
				res.Header.Set("Content-Type", "application/json")
				return res, nil
			case 3:
				// Retry with token fails at transport level
				return nil, errors.New("simulated network connection drop on retry")
			default:
				return nil, errors.New("unexpected request")
			}
		}),
	}

	w := &quayAPIWrapper{
		baseURL:         "http://example.com",
		httpClient:      client,
		maxResponseSize: 10 * 1024 * 1024,
		cachedTokens:    make(map[string]string),
	}

	_, err := w.DoRequest(ctx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
	require.Error(t, err)
	// Verify that the error is NOT "http: read on closed response body"
	assert.NotContains(t, err.Error(), "closed response body")
	// Verify that the actual transport error on retry is reported, not the stale 401 unauthorized body
	assert.NotContains(t, err.Error(), "unauthorized access")
	assert.Contains(t, err.Error(), "simulated network connection drop on retry")
	assert.Contains(t, err.Error(), "failed to retry request with auth token")
}

func TestQuayAdaptor_ChallengeRetryFailure_ReEntersRetryLoop(t *testing.T) {
	ctx := context.Background()

	reqCount := 0
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			reqCount++
			switch reqCount {
			case 1:
				// Initial request returns 401 with challenge header
				res := &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
				}
				res.Header.Set("WWW-Authenticate", `Bearer realm="http://example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
				return res, nil
			case 2:
				// Challenge token fetch succeeds
				res := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"token": "valid-token"}`)),
				}
				res.Header.Set("Content-Type", "application/json")
				return res, nil
			case 3:
				// First retry with token fails with simulated connection drop
				assert.Equal(t, "Bearer valid-token", req.Header.Get("Authorization"))
				return nil, errors.New("simulated network connection drop on retry")
			case 4:
				// Next attempt in retry loop succeeds with 200 OK using cached/attempt token
				assert.Equal(t, "Bearer valid-token", req.Header.Get("Authorization"))
				res := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"status": "scanned", "tags": []}`)),
				}
				res.Header.Set("Content-Type", "application/json")
				return res, nil
			default:
				return nil, errors.New("unexpected request")
			}
		}),
	}

	w := &quayAPIWrapper{
		baseURL:         "http://example.com",
		httpClient:      client,
		maxResponseSize: 10 * 1024 * 1024,
		maxRetries:      2,
		retryBackoff:    5 * time.Millisecond,
		cachedTokens:    make(map[string]string),
	}

	data, err := w.DoRequest(ctx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
	require.NoError(t, err)
	assert.Contains(t, string(data), "scanned")
	assert.Equal(t, 4, reqCount)
}

func TestQuayAdaptor_ChallengeTokenFetchError_Propagated(t *testing.T) {
	ctx := context.Background()

	t.Run("token service outage 503 is reported as actual cause rather than 401", func(t *testing.T) {
		reqCount := 0
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				reqCount++
				switch reqCount {
				case 1:
					res := &http.Response{
						StatusCode: http.StatusUnauthorized,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
					}
					res.Header.Set("WWW-Authenticate", `Bearer realm="http://example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
					return res, nil
				case 2:
					res := &http.Response{
						StatusCode: http.StatusServiceUnavailable,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"error": "token service outage"}`)),
					}
					return res, nil
				default:
					return nil, errors.New("unexpected request")
				}
			}),
		}

		w := &quayAPIWrapper{
			baseURL:         "http://example.com",
			httpClient:      client,
			maxResponseSize: 10 * 1024 * 1024,
			cachedTokens:    make(map[string]string),
		}

		_, err := w.DoRequest(ctx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "unauthorized access")
		assert.Contains(t, err.Error(), "failed to fetch auth challenge token")
		assert.Contains(t, err.Error(), "auth challenge endpoint returned status 503")
	})

	t.Run("token service redirect policy rejection is reported as actual cause rather than 401", func(t *testing.T) {
		// baseURL is https, realm is http (scheme downgrade)
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				res := &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
				}
				res.Header.Set("WWW-Authenticate", `Bearer realm="http://insecure.example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
				return res, nil
			}),
		}

		w := &quayAPIWrapper{
			baseURL:         "https://example.com",
			httpClient:      client,
			maxResponseSize: 10 * 1024 * 1024,
			cachedTokens:    make(map[string]string),
		}

		_, err := w.DoRequest(ctx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "unauthorized access")
		assert.Contains(t, err.Error(), "failed to fetch auth challenge token")
		assert.Contains(t, err.Error(), "scheme downgrade from https")
	})

	t.Run("context cancellation during token fetch preserves cancellation identity", func(t *testing.T) {
		cancellingCtx, cancel := context.WithCancel(ctx)
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/v2/auth" {
					cancel()
					return nil, context.Canceled
				}
				res := &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
				}
				res.Header.Set("WWW-Authenticate", `Bearer realm="http://example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
				return res, nil
			}),
		}

		w := &quayAPIWrapper{
			baseURL:         "http://example.com",
			httpClient:      client,
			maxResponseSize: 10 * 1024 * 1024,
			cachedTokens:    make(map[string]string),
		}

		_, err := w.DoRequest(cancellingCtx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

func TestQuayAdaptor_ChallengeRetryRedirectPolicyRejection(t *testing.T) {
	ctx := context.Background()

	reqCount := 0
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			reqCount++
			switch reqCount {
			case 1:
				res := &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"message": "unauthorized access", "status": 401}`)),
				}
				res.Header.Set("WWW-Authenticate", `Bearer realm="https://example.com/v2/auth",service="quay.io",scope="repository:org/repo:pull"`)
				return res, nil
			case 2:
				res := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"token": "valid-token"}`)),
				}
				res.Header.Set("Content-Type", "application/json")
				return res, nil
			case 3:
				// Retry request returns redirect error
				return nil, errors.New("refusing redirect to http://insecure.example.com: scheme downgrade from https")
			default:
				return nil, errors.New("unexpected request")
			}
		}),
	}

	w := &quayAPIWrapper{
		baseURL:         "https://example.com",
		httpClient:      client,
		maxResponseSize: 10 * 1024 * 1024,
		cachedTokens:    make(map[string]string),
	}

	_, err := w.DoRequest(ctx, http.MethodGet, "/api/v1/repository/org/repo/tag/")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unauthorized access")
	assert.Contains(t, err.Error(), "failed to retry request with auth token")
	assert.Contains(t, err.Error(), "scheme downgrade from https")
}

func TestQuayAdaptor_MismatchedRegistryRejection(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	adaptor := NewQuayAdaptor()
	err := adaptor.Login(ctx, server.URL, RegistryCredentials{})
	require.NoError(t, err)

	img := []ContainerImageIdentifier{
		{Registry: "docker.io", Repository: "myorg/myrepo", Tag: "latest"},
	}

	statuses, statusErr := adaptor.GetImagesScanStatus(ctx, img)
	require.Error(t, statusErr)
	assert.Contains(t, statusErr.Error(), "does not match quay registry")
	require.Len(t, statuses, 1)

	reports, reportErr := adaptor.GetImagesVulnerabilities(ctx, img)
	require.Error(t, reportErr)
	assert.Contains(t, reportErr.Error(), "does not match quay registry")
	require.Len(t, reports, 1)
}

func TestQuayAdaptor_CVSSScoreEmptyString_Regression(t *testing.T) {
	ctx := context.Background()
	const (
		org    = "coreos"
		repo   = "etcd"
		digest = "sha256:etcd350digest1234567890abcdef"
	)

	// Live Quay security response structure for coreos/etcd:v3.5.0 containing
	// empty string CVSS score ("Score": "") as well as numeric score.
	liveEtcdSecurityResponse := []byte(`{
		"status": "scanned",
		"data": {
			"Layer": {
				"Name": "` + digest + `",
				"Features": [
					{
						"Name": "etcd",
						"Version": "3.5.0",
						"Vulnerabilities": [
							{
								"Name": "CVE-2023-32082",
								"Severity": "High",
								"Description": "etcd lease revoke vulnerability",
								"Link": "https://nvd.nist.gov/vuln/detail/CVE-2023-32082",
								"FixedBy": "3.5.9",
								"Metadata": {
									"NVD": {
										"CVSSv3": {
											"Score": "",
											"Vectors": ""
										}
									}
								}
							},
							{
								"Name": "CVE-2023-44487",
								"Severity": "Critical",
								"Description": "HTTP/2 Rapid Reset",
								"Link": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
								"FixedBy": "",
								"Metadata": {
									"NVD": {
										"CVSSv3": {
											"Score": 7.5,
											"Vectors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
										}
									}
								}
							},
							{
								"Name": "CVE-2023-39325",
								"Severity": "Medium",
								"Description": "golang net/http issue",
								"Metadata": {
									"NVD": {
										"CVSSv3": {
											"Score": null
										}
									}
								}
							},
							{
								"Name": "CVE-2023-0001",
								"Severity": "Low",
								"Description": "unspecified issue"
							}
						]
					}
				]
			}
		}
	}`)

	mock := newMockQuayAPI()
	securityPath := quayManifestSecurityPath(org, repo, digest, true)
	mock.responses[securityPath] = liveEtcdSecurityResponse

	adaptor := NewQuayAdaptor()
	adaptor.client = mock
	adaptor.registryHost = "quay.io"

	images := []ContainerImageIdentifier{
		{Registry: "quay.io", Repository: "coreos/etcd", Hash: digest},
	}

	reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 4)

	vulnMap := make(map[string]Vulnerability)
	for _, v := range reports[0].Vulnerabilities {
		vulnMap[v.ID] = v
	}

	// CVE-2023-32082 had Score: ""
	v1, exists := vulnMap["CVE-2023-32082"]
	require.True(t, exists)
	assert.Equal(t, "High", v1.Severity)
	assert.Contains(t, v1.Description, "etcd lease revoke vulnerability")
	assert.Contains(t, v1.Description, "fixed in 3.5.9")

	// CVE-2023-44487 had Score: 7.5
	v2, exists := vulnMap["CVE-2023-44487"]
	require.True(t, exists)
	assert.Equal(t, "Critical", v2.Severity)

	// CVE-2023-39325 had Score: null
	v3, exists := vulnMap["CVE-2023-39325"]
	require.True(t, exists)
	assert.Equal(t, "Medium", v3.Severity)

	// CVE-2023-0001 had no Metadata
	v4, exists := vulnMap["CVE-2023-0001"]
	require.True(t, exists)
	assert.Equal(t, "Low", v4.Severity)
}

func TestQuayAdaptor_RetriesAfterAuthentication_429And503(t *testing.T) {
	ctx := context.Background()

	t.Run("429 Too Many Requests after auth challenge triggers retry and succeeds", func(t *testing.T) {
		var reqCount atomic.Int32
		var serverURL string
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := reqCount.Add(1)
			auth := r.Header.Get("Authorization")

			switch count {
			case 1:
				// First request: unauthenticated, issue challenge
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:myorg/myrepo:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}`))
			case 2:
				// Auth challenge request to /v2/auth
				if !assert.Equal(t, "/v2/auth", r.URL.Path) {
					http.Error(w, "unexpected auth path", http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token": "test-challenge-token-429"}`))
			case 3:
				// Retried request with token: return 429 Too Many Requests
				assert.Equal(t, "Bearer test-challenge-token-429", auth)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"message": "rate limit temporarily exceeded", "status": 429}`))
			case 4:
				// Subsequent retry after rate-limiting: succeeds with 200 OK
				assert.Equal(t, "Bearer test-challenge-token-429", auth)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "scanned", "data": "recovered-from-429"}`))
			default:
				http.Error(w, "unexpected extra request", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		mu.Lock()
		serverURL = server.URL
		mu.Unlock()

		wrapper := &quayAPIWrapper{
			baseURL:         server.URL,
			httpClient:      server.Client(),
			maxResponseSize: 10 * 1024 * 1024,
			maxRetries:      3,
			retryBackoff:    5 * time.Millisecond,
			cachedTokens:    make(map[string]string),
		}

		data, err := wrapper.DoRequest(ctx, http.MethodGet, "/v2/myorg/myrepo/manifests/v1.0.0")
		require.NoError(t, err)
		assert.Contains(t, string(data), "recovered-from-429")
		assert.Equal(t, int32(4), reqCount.Load())
	})

	t.Run("503 Service Unavailable after auth challenge triggers backoff and succeeds", func(t *testing.T) {
		var reqCount atomic.Int32
		var serverURL string
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := reqCount.Add(1)
			auth := r.Header.Get("Authorization")

			switch count {
			case 1:
				// First request: unauthenticated, issue challenge
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:myorg/myrepo:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}`))
			case 2:
				// Auth challenge request to /v2/auth
				if !assert.Equal(t, "/v2/auth", r.URL.Path) {
					http.Error(w, "unexpected auth path", http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token": "test-challenge-token-503"}`))
			case 3:
				// Retried request with token: return 503 Service Unavailable
				assert.Equal(t, "Bearer test-challenge-token-503", auth)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"message": "quay database temporarily unavailable", "status": 503}`))
			case 4:
				// Subsequent retry after backoff: succeeds with 200 OK
				assert.Equal(t, "Bearer test-challenge-token-503", auth)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "scanned", "data": "recovered-from-503"}`))
			default:
				http.Error(w, "unexpected extra request", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		mu.Lock()
		serverURL = server.URL
		mu.Unlock()

		wrapper := &quayAPIWrapper{
			baseURL:         server.URL,
			httpClient:      server.Client(),
			maxResponseSize: 10 * 1024 * 1024,
			maxRetries:      3,
			retryBackoff:    5 * time.Millisecond,
			cachedTokens:    make(map[string]string),
		}

		data, err := wrapper.DoRequest(ctx, http.MethodGet, "/v2/myorg/myrepo/manifests/v1.0.0")
		require.NoError(t, err)
		assert.Contains(t, string(data), "recovered-from-503")
		assert.Equal(t, int32(4), reqCount.Load())
	})

	t.Run("429 and 503 retry exhaustion after challenge returns error", func(t *testing.T) {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
			t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
				var reqCount atomic.Int32
				var serverURL string
				var mu sync.Mutex

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					count := reqCount.Add(1)
					if count == 1 {
						mu.Lock()
						realm := serverURL + "/v2/auth"
						mu.Unlock()
						w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:org/repo:pull"`, realm))
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"message": "auth required"}`))
						return
					}
					if r.URL.Path == "/v2/auth" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"token": "persistent-token"}`))
						return
					}
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					_, _ = fmt.Fprintf(w, `{"message": "permanent failure", "status": %d}`, status)
				}))
				defer server.Close()

				mu.Lock()
				serverURL = server.URL
				mu.Unlock()

				wrapper := &quayAPIWrapper{
					baseURL:         server.URL,
					httpClient:      server.Client(),
					maxResponseSize: 10 * 1024 * 1024,
					maxRetries:      1, // Only 1 retry allowed
					retryBackoff:    5 * time.Millisecond,
					cachedTokens:    make(map[string]string),
				}

				_, err := wrapper.DoRequest(ctx, http.MethodGet, "/v2/org/repo/manifests/latest")
				require.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("%d", status))
			})
		}
	})

	t.Run("API endpoint without v2 prefix retains auth token and recovers from 429", func(t *testing.T) {
		var reqCount atomic.Int32
		var serverURL string
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := reqCount.Add(1)
			auth := r.Header.Get("Authorization")

			switch count {
			case 1:
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:custom/app:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "auth required"}`))
			case 2:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token": "custom-app-token"}`))
			case 3:
				assert.Equal(t, "Bearer custom-app-token", auth)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"message": "rate limit", "status": 429}`))
			case 4:
				// Ensures Bearer token was preserved across the rate-limit retry
				assert.Equal(t, "Bearer custom-app-token", auth)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "recovered"}`))
			default:
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		mu.Lock()
		serverURL = server.URL
		mu.Unlock()

		wrapper := &quayAPIWrapper{
			baseURL:         server.URL,
			httpClient:      server.Client(),
			maxResponseSize: 10 * 1024 * 1024,
			maxRetries:      2,
			retryBackoff:    5 * time.Millisecond,
			cachedTokens:    make(map[string]string),
		}

		data, err := wrapper.DoRequest(ctx, http.MethodGet, "/api/v1/repository/custom/app/tag/")
		require.NoError(t, err)
		assert.Contains(t, string(data), "recovered")
	})
}

func TestQuayAdaptor_AuthChallenge_MaxConnsPerHost1(t *testing.T) {
	t.Run("successful challenge and retry on same host with single connection transport", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var reqCount atomic.Int32
		var serverURL string
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := reqCount.Add(1)
			switch count {
			case 1:
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:myorg/myrepo:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}`))
			case 2:
				assert.Equal(t, "/v2/auth", r.URL.Path)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token": "test-token"}`))
			case 3:
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer test-token", auth)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "success"}`))
			default:
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		mu.Lock()
		serverURL = server.URL
		mu.Unlock()

		customTransport := &http.Transport{
			MaxConnsPerHost: 1,
		}
		customClient := &http.Client{
			Transport: customTransport,
		}

		adaptor := NewQuayAdaptor(
			WithHTTPClient(customClient),
			WithInsecureHTTPCredentials(),
			WithTimeout(1*time.Second),
		)

		api := adaptor.clientFactory(server.URL, "", "", "")
		data, err := api.DoRequest(ctx, http.MethodGet, "/v2/myorg/myrepo/manifests/v1.0.0")
		require.NoError(t, err)
		assert.Contains(t, string(data), "success")
		assert.Equal(t, int32(3), reqCount.Load())
	})

	t.Run("challenge token failure does not deadlock single connection transport", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var reqCount atomic.Int32
		var serverURL string
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := reqCount.Add(1)
			switch count {
			case 1:
				mu.Lock()
				realm := serverURL + "/v2/auth"
				mu.Unlock()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="quay.io",scope="repository:myorg/myrepo:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}`))
			case 2:
				assert.Equal(t, "/v2/auth", r.URL.Path)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "access denied"}`))
			default:
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		mu.Lock()
		serverURL = server.URL
		mu.Unlock()

		customTransport := &http.Transport{
			MaxConnsPerHost: 1,
		}
		customClient := &http.Client{
			Transport: customTransport,
		}

		adaptor := NewQuayAdaptor(
			WithHTTPClient(customClient),
			WithInsecureHTTPCredentials(),
			WithTimeout(1*time.Second),
		)

		api := adaptor.clientFactory(server.URL, "", "", "")
		_, err := api.DoRequest(ctx, http.MethodGet, "/v2/myorg/myrepo/manifests/v1.0.0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth challenge endpoint returned status 403")
		assert.Equal(t, int32(2), reqCount.Load())
	})
}

func BenchmarkQuayAdaptor_GetImagesVulnerabilities_Single(b *testing.B) {
	fixtures := loadTestFixturesForBenchmark(b)
	digest := "sha256:enterprise1234567890abcdef"
	path := quayManifestSecurityPath("benchorg", "benchrepo", digest, true)

	mock := newMockQuayAPI()
	mock.responses[path] = fixtures["enterprise_multirepo_scan"]

	adaptor := NewQuayAdaptor()
	adaptor.client = mock

	img := []ContainerImageIdentifier{
		{Registry: "quay.io", Repository: "benchorg/benchrepo", Hash: digest},
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := adaptor.GetImagesVulnerabilities(ctx, img)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkQuayAdaptor_GetImagesVulnerabilities_Batch(b *testing.B) {
	fixtures := loadTestFixturesForBenchmark(b)
	mock := newMockQuayAPI()

	var images []ContainerImageIdentifier
	for i := 0; i < 20; i++ {
		digest := fmt.Sprintf("sha256:digest%03d", i)
		repo := fmt.Sprintf("benchorg/repo%03d", i)
		path := quayManifestSecurityPath("benchorg", fmt.Sprintf("repo%03d", i), digest, true)
		mock.responses[path] = fixtures["enterprise_multirepo_scan"]
		images = append(images, ContainerImageIdentifier{
			Registry:   "quay.io",
			Repository: repo,
			Hash:       digest,
		})
	}

	adaptor := NewQuayAdaptor()
	adaptor.client = mock
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		if len(reports) != 20 {
			b.Fatalf("expected 20 reports, got %d", len(reports))
		}
	}
}

func BenchmarkQuayAdaptor_ExtractQuayRepo(b *testing.B) {
	adaptor := NewQuayAdaptor()
	repoStr := "quay.io/myenterprise-organization/myapplication-service"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = adaptor.extractRepo(repoStr)
	}
}

func BenchmarkQuayAdaptor_ParseQuayTimestamp(b *testing.B) {
	ts := "2023-10-15T12:30:00Z"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseQuayTimestamp(ts)
	}
}

func BenchmarkQuayAdaptor_NormalizeQuaySeverity(b *testing.B) {
	severities := []string{"Defcon1", "Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeQuaySeverity(severities[i%len(severities)])
	}
}

func loadTestFixtures(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("testdata/quay_fixtures.json")
	require.NoError(t, err)
	var fixtures map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &fixtures))
	return fixtures
}

func loadTestFixturesForBenchmark(b *testing.B) map[string]json.RawMessage {
	b.Helper()
	data, err := os.ReadFile("testdata/quay_fixtures.json")
	if err != nil {
		b.Fatalf("failed to read test fixtures: %v", err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		b.Fatalf("failed to unmarshal test fixtures: %v", err)
	}
	return fixtures
}
