package imagescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGitlabAPI struct {
	responses map[string][]byte
	errors    map[string]error
	callCount map[string]int
}

func (m *mockGitlabAPI) DoGraphQL(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	if m.callCount == nil {
		m.callCount = make(map[string]int)
	}

	fullPath, ok := variables["fullPath"].(string)
	if !ok {
		return nil, fmt.Errorf("missing fullPath variable")
	}

	key := fullPath
	if after, ok := variables["after"].(string); ok && after != "" {
		key += "_" + after
	}

	m.callCount[key]++

	if err, ok := m.errors[key]; ok {
		return nil, err
	}
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("mock key not found: %s", key)
}

func TestGitlabAdaptor_DescribeAdaptor(t *testing.T) {
	adaptor := NewGitlabAdaptor()
	assert.Equal(t, "GitLab Container Registry Vulnerability Adaptor", adaptor.DescribeAdaptor())
}

func TestGitlabAdaptor_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer badtoken" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized body test snippet"))
				return
			}
			if auth == "Bearer nulluser" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":{"currentUser":null}}`))
				return
			}
			if auth == "Bearer grapherror" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"errors":[{"message":"Forbidden"}]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"currentUser":{"username":"testuser"}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		registry    string
		credentials RegistryCredentials
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid registry format and auth",
			registry:    server.URL + "/", // Test trailing slash removal
			credentials: RegistryCredentials{Token: "goodtoken"},
			wantErr:     false,
		},
		{
			name:        "auth failure with truncated body",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "badtoken"},
			wantErr:     true,
			errMsg:      "unauthorized body test snippet",
		},
		{
			name:        "null current user",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "nulluser"},
			wantErr:     true,
			errMsg:      "invalid token or insufficient scopes",
		},
		{
			name:        "graphql error during login",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "grapherror"},
			wantErr:     true,
			errMsg:      "graphql error during login: Forbidden",
		},
		{
			name:        "missing token",
			registry:    server.URL,
			credentials: RegistryCredentials{Username: "test", Password: "password"},
			wantErr:     true,
			errMsg:      "requires a personal or project access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewGitlabAdaptor()
			err := adaptor.Login(context.Background(), tt.registry, tt.credentials)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSplitGitLabProjectPath(t *testing.T) {
	tests := []struct {
		repo             string
		expectedFullPath string
		expectedImage    string
		wantErr          bool
	}{
		{"my-group/my-project/my-image", "my-group/my-project", "my-image", false},
		{"my-group/subgroup/my-project/my-image", "my-group/subgroup/my-project", "my-image", false},
		{"my-group", "", "", true},          // Missing slash
		{"/my-image", "", "", true},         // Invalid leading slash making fullPath empty
		{"my-group/my-image", "", "", true}, // Only one slash, fails 'at least group/project/image'
		{"/my-group/my-project/my-image", "my-group/my-project", "my-image", false}, // leading slash valid if rest is ok
	}

	for _, tt := range tests {
		t.Run(tt.repo, func(t *testing.T) {
			fullPath, imageName, err := splitGitLabProjectPath(tt.repo)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFullPath, fullPath)
				assert.Equal(t, tt.expectedImage, imageName)
			}
		})
	}
}

func TestGitlabAdaptor_GetImagesScanStatus(t *testing.T) {
	mockAPI := &mockGitlabAPI{
		responses: map[string][]byte{
			"my-group/my-project": []byte(`{
				"data": {
					"project": {
						"vulnerabilities": {
							"nodes": [
								{ "title": "CVE-2023-1234" }
							]
						}
					}
				}
			}`),
			"my-group/empty-project": []byte(`{
				"data": {
					"project": {
						"vulnerabilities": {
							"nodes": []
						}
					}
				}
			}`),
			"my-group/null-project": []byte(`{
				"data": {
					"project": null
				}
			}`),
			"my-group/error-project": []byte(`{
				"errors": [
					{ "message": "Project not found" }
				]
			}`),
			"my-group/malformed-project": []byte(`{ malformed json }`),
		},
		errors: map[string]error{
			"my-group/api-error-project": fmt.Errorf("api error"),
		},
	}

	adaptor := NewGitlabAdaptor()
	adaptor.client = mockAPI

	imageIDs := []ContainerImageIdentifier{
		{Repository: "my-group/my-project/my-image", Hash: "sha256:123"},
		{Repository: "my-group/my-project/my-image2", Hash: "sha256:456"}, // Will test caching since it's the same project
		{Repository: "my-group/empty-project/my-image", Hash: "sha256:456"},
		{Repository: "my-group/null-project/my-image", Hash: "sha256:789"}, // Null project
		{Repository: "my-group/error-project/my-image", Hash: "sha256:789"},
		{Repository: "my-group/api-error-project/my-image", Hash: "sha256:000"},
		{Repository: "invalidformat", Hash: "sha256:111"},
		{Repository: "my-group/malformed-project/my-image", Hash: "sha256:999"},
	}

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), imageIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid gitlab repository format")
	assert.Contains(t, err.Error(), "graphql error: Project not found")
	assert.Contains(t, err.Error(), "project not found or permission denied")
	assert.Contains(t, err.Error(), "api error")
	assert.Contains(t, err.Error(), "failed to parse scan status payload")

	assert.Len(t, statuses, 8)

	assert.True(t, statuses[0].IsScanAvailable)  // Found nodes
	assert.True(t, statuses[1].IsScanAvailable)  // Found nodes (cached!)
	assert.True(t, statuses[2].IsScanAvailable)  // Empty nodes but no GraphQL error means scanned
	assert.False(t, statuses[3].IsScanAvailable) // Null Project
	assert.False(t, statuses[4].IsScanAvailable) // GraphQL Error
	assert.False(t, statuses[5].IsScanAvailable) // API Error
	assert.False(t, statuses[6].IsScanAvailable) // Format Error
	assert.False(t, statuses[7].IsScanAvailable) // Malformed JSON

	// Verify caching - 'my-group/my-project' should only have 1 call
	assert.Equal(t, 1, mockAPI.callCount["my-group/my-project"])
}

func TestGitlabAdaptor_GetImagesVulnerabilities(t *testing.T) {
	mockAPI := &mockGitlabAPI{
		responses: map[string][]byte{
			"my-group/my-project": []byte(`{
				"data": {
					"project": {
						"vulnerabilities": {
							"pageInfo": {
								"hasNextPage": true,
								"endCursor": "cursor123"
							},
							"nodes": [
								{
									"title": "CVE-2023-1234",
									"severity": "High",
									"description": "Test vulnerability",
									"location": {
										"image": "registry.gitlab.com/my-group/my-project/app:latest"
									}
								},
								{
									"title": "CVE-2023-5678",
									"severity": "Low",
									"description": "App Backend vulnerability",
									"location": {
										"image": "registry.gitlab.com/my-group/my-project/app-backend:latest"
									}
								},
								{
									"title": "CVE-2023-0000",
									"severity": "Critical",
									"description": "Digest vulnerability",
									"location": {
										"image": "registry.gitlab.com/my-group/my-project/app@sha256:112233"
									}
								}
							]
						}
					}
				}
			}`),
			"my-group/my-project_cursor123": []byte(`{
				"data": {
					"project": {
						"vulnerabilities": {
							"pageInfo": {
								"hasNextPage": false,
								"endCursor": ""
							},
							"nodes": [
								{
									"title": "CVE-2023-9999",
									"severity": "Critical",
									"description": "Page 2 vuln",
									"location": {
										"image": "registry.gitlab.com/my-group/my-project/app:latest"
									}
								}
							]
						}
					}
				}
			}`),
		},
	}

	adaptor := NewGitlabAdaptor()
	adaptor.client = mockAPI

	// Test case 1: Boundary matching. 'app' should NOT match 'app-backend'
	imageIDs := []ContainerImageIdentifier{
		{Repository: "my-group/my-project/app", Tag: "latest"},
		{Repository: "my-group/my-project/app", Tag: "latest"}, // Second one tests cache
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), imageIDs)

	assert.NoError(t, err)
	assert.Len(t, reports, 2)
	assert.Len(t, reports[0].Vulnerabilities, 2) // One from page 1, one from page 2. Excludes app-backend!

	vuln1 := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln1.ID)
	assert.Equal(t, "High", vuln1.Severity)

	vuln2 := reports[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-9999", vuln2.ID)
	assert.Equal(t, "Critical", vuln2.Severity)

	// Verify caching - 'my-group/my-project' should only have 1 call for base and 1 for paginated
	assert.Equal(t, 1, mockAPI.callCount["my-group/my-project"])
	assert.Equal(t, 1, mockAPI.callCount["my-group/my-project_cursor123"])

	// Test case 2: Digest matching priority
	imageIDsHash := []ContainerImageIdentifier{
		{Repository: "my-group/my-project/app", Hash: "sha256:112233"},
	}

	reportsHash, err := adaptor.GetImagesVulnerabilities(context.Background(), imageIDsHash)
	assert.NoError(t, err)
	assert.Len(t, reportsHash, 1)
	assert.Len(t, reportsHash[0].Vulnerabilities, 1) // Should only match the digest vulnerability!

	vulnDigest := reportsHash[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-0000", vulnDigest.ID)

	// Test case 3: Unmatched digest (simulate API limitation)
	imageIDsUnmatched := []ContainerImageIdentifier{
		{Repository: "my-group/my-project/app", Hash: "sha256:unknown"},
	}

	reportsUnmatched, err := adaptor.GetImagesVulnerabilities(context.Background(), imageIDsUnmatched)
	assert.NoError(t, err)
	assert.Len(t, reportsUnmatched, 1)
	assert.Len(t, reportsUnmatched[0].Vulnerabilities, 0) // Should match nothing because the digest isn't present
}

func TestGitlabAdaptor_GetImagesVulnerabilitiesRejectsStalledPagination(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string][]byte
		wantError string
		wantCalls map[string]int
	}{
		{
			name: "missing cursor",
			responses: map[string][]byte{
				"my-group/my-project": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":""},
						"nodes":[]
					}}}
				}`),
			},
			wantError: "without an end cursor",
			wantCalls: map[string]int{"my-group/my-project": 1},
		},
		{
			name: "immediately repeated cursor",
			responses: map[string][]byte{
				"my-group/my-project": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":"cursor-a"},
						"nodes":[]
					}}}
				}`),
				"my-group/my-project_cursor-a": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":"cursor-a"},
						"nodes":[]
					}}}
				}`),
			},
			wantError: "repeated cursor \"cursor-a\"",
			wantCalls: map[string]int{
				"my-group/my-project":          1,
				"my-group/my-project_cursor-a": 1,
			},
		},
		{
			name: "cursor cycle",
			responses: map[string][]byte{
				"my-group/my-project": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":"cursor-a"},
						"nodes":[]
					}}}
				}`),
				"my-group/my-project_cursor-a": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":"cursor-b"},
						"nodes":[]
					}}}
				}`),
				"my-group/my-project_cursor-b": []byte(`{
					"data":{"project":{"vulnerabilities":{
						"pageInfo":{"hasNextPage":true,"endCursor":"cursor-a"},
						"nodes":[]
					}}}
				}`),
			},
			wantError: "repeated cursor \"cursor-a\"",
			wantCalls: map[string]int{
				"my-group/my-project":          1,
				"my-group/my-project_cursor-a": 1,
				"my-group/my-project_cursor-b": 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockGitlabAPI{responses: tt.responses}
			adaptor := NewGitlabAdaptor()
			adaptor.client = mockAPI

			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{{
				Repository: "my-group/my-project/app",
				Tag:        "latest",
			}})

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
			require.Len(t, reports, 1)
			assert.Empty(t, reports[0].Vulnerabilities)
			assert.Equal(t, tt.wantCalls, mockAPI.callCount)
		})
	}
}

func TestNextGitLabVulnerabilityCursorEnforcesPageLimit(t *testing.T) {
	seen := make(map[string]struct{})

	cursor, more, err := nextGitLabVulnerabilityCursor(true, "final-cursor", seen, maxGitLabVulnerabilityPages)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "1000-page safety limit")
	assert.Empty(t, cursor)
	assert.False(t, more)
	assert.Empty(t, seen)
}

func TestNextGitLabVulnerabilityCursorAcceptsValidProgress(t *testing.T) {
	tests := []struct {
		name        string
		hasNextPage bool
		endCursor   string
		wantCursor  string
		wantMore    bool
	}{
		{
			name:       "terminal page",
			endCursor:  "ignored-terminal-cursor",
			wantCursor: "",
		},
		{
			name:        "fresh next page",
			hasNextPage: true,
			endCursor:   "cursor-2",
			wantCursor:  "cursor-2",
			wantMore:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := map[string]struct{}{"cursor-1": {}}
			cursor, more, err := nextGitLabVulnerabilityCursor(tt.hasNextPage, tt.endCursor, seen, 1)

			require.NoError(t, err)
			assert.Equal(t, tt.wantCursor, cursor)
			assert.Equal(t, tt.wantMore, more)
			if tt.wantMore {
				assert.Contains(t, seen, tt.wantCursor)
			}
		})
	}
}

func TestNormalizeGitlabSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "Critical"},
		{"critical", "Critical"},
		{"HIGH", "High"},
		{"MEDIUM", "Medium"},
		{"LOW", "Low"},
		{"INFO", "Negligible"},
		{"unknown", "Unknown"},
		{"invalid", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeGitLabSeverity(tt.input))
		})
	}
}

func TestGitlabAdaptor_GetImagesInformation(t *testing.T) {
	adaptor := NewGitlabAdaptor()
	adaptor.client = &mockGitlabAPI{}

	infos, err := adaptor.GetImagesInformation(context.Background(), []ContainerImageIdentifier{{}})
	assert.NoError(t, err)
	assert.Len(t, infos, 1)
}

func TestGitlabAdaptor_Destroy(t *testing.T) {
	adaptor := NewGitlabAdaptor()
	assert.NoError(t, adaptor.Destroy())
}

func TestImageMatches(t *testing.T) {
	t.Run("matches by digest with registry path prefix", func(t *testing.T) {
		id := ContainerImageIdentifier{Repository: "group/app", Hash: "sha256:abc"}
		assert.True(t, imageMatches("registry.gitlab.com/group/app@sha256:abc", id))
	})

	t.Run("matches by tag with no prefix", func(t *testing.T) {
		id := ContainerImageIdentifier{Repository: "app", Tag: "latest"}
		assert.True(t, imageMatches("app:latest", id))
	})

	t.Run("does not match a different repo that happens to share a suffix", func(t *testing.T) {
		id := ContainerImageIdentifier{Repository: "app", Tag: "latest"}
		assert.False(t, imageMatches("registry.gitlab.com/group/webapp:latest", id))
	})

	t.Run("does not match a different repo sharing a suffix, by digest", func(t *testing.T) {
		id := ContainerImageIdentifier{Repository: "app", Hash: "sha256:abc"}
		assert.False(t, imageMatches("registry.gitlab.com/group/myapp@sha256:abc", id))
	})
}
