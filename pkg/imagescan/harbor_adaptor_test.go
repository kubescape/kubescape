package imagescan

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHarborAPI struct {
	responses map[string][]byte
	errors    map[string]error
}

func (m *mockHarborAPI) DoRequest(ctx context.Context, method, path string) ([]byte, error) {
	if err, ok := m.errors[path]; ok {
		return nil, err
	}
	if resp, ok := m.responses[path]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("mock url not found: %s", path)
}

func TestHarborAdaptor_DescribeAdaptor(t *testing.T) {
	adaptor := NewHarborAdaptor()
	assert.Equal(t, "Harbor Container Registry Vulnerability Adaptor", adaptor.DescribeAdaptor())
}

func TestHarborAdaptor_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			auth := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("bad:bad"))
			if auth == expectedAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"with_chartmuseum": true}`))
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
			registry:    server.URL,
			credentials: RegistryCredentials{Username: "robot$user", Password: "password"},
			wantErr:     false,
		},
		{
			name:        "auth failure",
			registry:    server.URL,
			credentials: RegistryCredentials{Username: "bad", Password: "bad"},
			wantErr:     true,
			errMsg:      "failed to connect to harbor",
		},
		{
			name:        "network failure",
			registry:    "http://127.0.0.1:0", // Invalid port
			credentials: RegistryCredentials{},
			wantErr:     true,
			errMsg:      "failed to connect to harbor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewHarborAdaptor()
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

func TestHarborAPIWrapperRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("123456789"))
	}))
	defer server.Close()

	wrapper := &harborAPIWrapper{
		baseURL:         server.URL,
		httpClient:      server.Client(),
		maxResponseSize: 8,
	}

	body, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/vulnerabilities")

	assert.Nil(t, body)
	assert.ErrorContains(t, err, "exceeds the 8-byte limit")
}

func TestExtractProjectAndRepo(t *testing.T) {
	tests := []struct {
		repo            string
		expectedProject string
		expectedRepo    string
		wantErr         bool
	}{
		{"myproject/myrepo", "myproject", "myrepo", false},
		{"myproject/nested/repo", "myproject", "nested/repo", false},
		{"myrepo", "", "", true}, // Missing slash
	}

	for _, tt := range tests {
		t.Run(tt.repo, func(t *testing.T) {
			project, repo, err := extractProjectAndRepo(tt.repo)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedProject, project)
				assert.Equal(t, tt.expectedRepo, repo)
			}
		})
	}
}

func TestHarborRepositoryPathSegment(t *testing.T) {
	tests := map[string]string{
		"api":                  "api",
		"backend/api":          "backend%252Fapi",
		"team/backend/service": "team%252Fbackend%252Fservice",
	}

	for repository, expected := range tests {
		t.Run(repository, func(t *testing.T) {
			assert.Equal(t, expected, harborRepositoryPathSegment(repository))
		})
	}
}

func TestHarborAPIWrapperPreservesNestedRepositoryAsOnePathSegment(t *testing.T) {
	var requestURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	wrapper := &harborAPIWrapper{
		baseURL:         server.URL,
		httpClient:      server.Client(),
		maxResponseSize: maxRegistryAPIResponseBytes,
	}
	path := "/api/v2.0/projects/platform/repositories/backend%252Fapi/artifacts/latest"

	_, err := wrapper.DoRequest(context.Background(), http.MethodGet, path)

	assert.NoError(t, err)
	assert.Equal(t, path, requestURI)
}

func TestHarborAdaptor_GetImagesScanStatus(t *testing.T) {
	mockAPI := &mockHarborAPI{
		responses: map[string][]byte{
			"/api/v2.0/projects/myproject/repositories/myrepo/artifacts/sha256:123?with_scan_overview=true": []byte(`{
				"scan_overview": {
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scan_status": "Success",
						"end_time": "2023-01-01T10:00:00Z"
					}
				}
			}`),
			"/api/v2.0/projects/myproject/repositories/team%252Fbackend/artifacts/sha256:nested?with_scan_overview=true": []byte(`{
				"scan_overview": {
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scan_status": "Success",
						"end_time": "2024-02-03T10:00:00Z"
					}
				}
			}`),
			"/api/v2.0/projects/myproject/repositories/pendingrepo/artifacts/sha256:456?with_scan_overview=true": []byte(`{
				"scan_overview": {
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scan_status": "Pending",
						"end_time": "2023-01-01T10:00:00Z"
					}
				}
			}`),
			"/api/v2.0/projects/myproject/repositories/malformedrepo/artifacts/sha256:999?with_scan_overview=true": []byte(`{
				malformed json
			}`),
		},
		errors: map[string]error{
			"/api/v2.0/projects/myproject/repositories/errorrepo/artifacts/sha256:789?with_scan_overview=true": fmt.Errorf("api error"),
		},
	}

	adaptor := NewHarborAdaptor()
	adaptor.client = mockAPI

	imageIDs := []ContainerImageIdentifier{
		{Repository: "myproject/myrepo", Hash: "sha256:123"},
		{Repository: "myproject/pendingrepo", Hash: "sha256:456"},
		{Repository: "myproject/errorrepo", Hash: "sha256:789"},
		{Repository: "myproject/notfound", Hash: "sha256:000"},      // Mock won't find this
		{Repository: "invalidformat", Hash: "sha256:111"},           // Format error
		{Repository: "myproject/malformedrepo", Hash: "sha256:999"}, // Malformed payload
		{Repository: "myproject/team/backend", Hash: "sha256:nested"},
	}

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), imageIDs)

	assert.Error(t, err) // Should have aggErr from errorrepo, notfound, invalidformat, malformedrepo
	assert.Contains(t, err.Error(), "failed to parse scan status payload")
	assert.Contains(t, err.Error(), "invalid harbor repository format")
	assert.Contains(t, err.Error(), "api error")

	assert.Len(t, statuses, 7)

	assert.True(t, statuses[0].IsScanAvailable)
	assert.Equal(t, 2023, statuses[0].LastScanDate.Year())

	assert.False(t, statuses[1].IsScanAvailable) // Pending
	assert.False(t, statuses[2].IsScanAvailable) // errorrepo
	assert.False(t, statuses[4].IsScanAvailable) // invalidformat
	assert.False(t, statuses[5].IsScanAvailable) // malformedrepo
	assert.True(t, statuses[6].IsScanAvailable)  // nested Harbor repository
}

func TestLatestSuccessfulHarborScan(t *testing.T) {
	tests := []struct {
		name          string
		overviews     map[string]harborScanOverview
		wantAvailable bool
		wantTime      string
	}{
		{
			name:          "no scan overview",
			overviews:     nil,
			wantAvailable: false,
		},
		{
			name: "only unfinished scans",
			overviews: map[string]harborScanOverview{
				"scanner-a": {ScanStatus: "Pending", EndTime: "2025-04-05T10:00:00Z"},
				"scanner-b": {ScanStatus: "Running", EndTime: "2025-04-05T11:00:00Z"},
			},
			wantAvailable: false,
		},
		{
			name: "single successful scan",
			overviews: map[string]harborScanOverview{
				"scanner-a": {ScanStatus: "Success", EndTime: "2025-04-05T10:00:00Z"},
			},
			wantAvailable: true,
			wantTime:      "2025-04-05T10:00:00Z",
		},
		{
			name: "status matching is case insensitive",
			overviews: map[string]harborScanOverview{
				"scanner-a": {ScanStatus: "SUCCESS", EndTime: "2025-04-05T10:00:00Z"},
			},
			wantAvailable: true,
			wantTime:      "2025-04-05T10:00:00Z",
		},
		{
			name: "latest successful report wins",
			overviews: map[string]harborScanOverview{
				"application/vnd.scanner.old": {
					ScanStatus: "Success",
					EndTime:    "2024-01-02T03:04:05Z",
				},
				"application/vnd.scanner.new": {
					ScanStatus: "Success",
					EndTime:    "2025-06-07T08:09:10Z",
				},
				"application/vnd.scanner.pending": {
					ScanStatus: "Pending",
					EndTime:    "2026-07-08T09:10:11Z",
				},
			},
			wantAvailable: true,
			wantTime:      "2025-06-07T08:09:10Z",
		},
		{
			name: "malformed successful timestamp does not hide a valid one",
			overviews: map[string]harborScanOverview{
				"scanner-malformed": {ScanStatus: "Success", EndTime: "not-a-time"},
				"scanner-valid":     {ScanStatus: "Success", EndTime: "2025-06-07T08:09:10.123Z"},
			},
			wantAvailable: true,
			wantTime:      "2025-06-07T08:09:10.123Z",
		},
		{
			name: "newer failed report does not replace last successful scan",
			overviews: map[string]harborScanOverview{
				"scanner-success": {
					ScanStatus: "Success",
					EndTime:    "2025-06-07T08:09:10Z",
				},
				"scanner-failed": {
					ScanStatus: "Error",
					EndTime:    "2026-07-08T09:10:11Z",
				},
			},
			wantAvailable: true,
			wantTime:      "2025-06-07T08:09:10Z",
		},
		{
			name: "successful report without a usable time is still available",
			overviews: map[string]harborScanOverview{
				"scanner-a": {ScanStatus: "Success", EndTime: ""},
			},
			wantAvailable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			available, completedAt := latestSuccessfulHarborScan(tt.overviews)
			assert.Equal(t, tt.wantAvailable, available)

			if tt.wantTime == "" {
				assert.True(t, completedAt.IsZero())
				return
			}

			want, err := time.Parse(time.RFC3339, tt.wantTime)
			require.NoError(t, err)
			assert.Equal(t, want, completedAt)
		})
	}
}

func TestHarborAdaptor_GetImagesScanStatusUsesLatestSuccessfulReport(t *testing.T) {
	const statusPath = "/api/v2.0/projects/platform/repositories/service/artifacts/sha256:abc?with_scan_overview=true"
	client := &mockHarborAPI{
		responses: map[string][]byte{
			statusPath: []byte(`{
				"scan_overview": {
					"application/vnd.scanner.v1": {
						"scan_status": "Success",
						"end_time": "2023-03-01T12:00:00Z"
					},
					"application/vnd.scanner.v2": {
						"scan_status": "Success",
						"end_time": "2025-09-03T14:30:00Z"
					},
					"application/vnd.scanner.v3": {
						"scan_status": "Pending",
						"end_time": "2026-01-01T00:00:00Z"
					}
				}
			}`),
		},
		errors: map[string]error{},
	}
	adaptor := NewHarborAdaptor()
	adaptor.client = client

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{{
		Repository: "platform/service",
		Hash:       "sha256:abc",
	}})

	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].IsScanAvailable)
	assert.Equal(t, "2025-09-03T14:30:00Z", statuses[0].LastScanDate.Format(time.RFC3339))
}

func TestHarborAdaptor_GetImagesScanStatusIsStableAcrossMapIterations(t *testing.T) {
	overviews := map[string]harborScanOverview{
		"scanner-2019": {ScanStatus: "Success", EndTime: "2019-01-01T00:00:00Z"},
		"scanner-2021": {ScanStatus: "Success", EndTime: "2021-01-01T00:00:00Z"},
		"scanner-2023": {ScanStatus: "Success", EndTime: "2023-01-01T00:00:00Z"},
		"scanner-2025": {ScanStatus: "Success", EndTime: "2025-01-01T00:00:00Z"},
	}
	want, err := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		available, completedAt := latestSuccessfulHarborScan(overviews)
		assert.True(t, available)
		assert.Equal(t, want, completedAt)
	}
}

func TestHarborAdaptor_GetImagesVulnerabilities(t *testing.T) {
	mockAPI := &mockHarborAPI{
		responses: map[string][]byte{
			"/api/v2.0/projects/myproject/repositories/myrepo/artifacts/sha256:123/additions/vulnerabilities": []byte(`{
				"application/vnd.security.vulnerability.report; version=1.1": {
					"vulnerabilities": [
						{
							"id": "CVE-2023-1234",
							"severity": "High",
							"description": "Test vulnerability",
							"links": ["https://example.com/cve"]
						}
					]
				}
			}`),
			"/api/v2.0/projects/myproject/repositories/team%252Fbackend/artifacts/sha256:nested/additions/vulnerabilities": []byte(`{
				"application/vnd.security.vulnerability.report; version=1.1": {
					"vulnerabilities": [
						{
							"id": "CVE-NESTED",
							"severity": "Critical",
							"description": "Nested repository finding",
							"links": []
						}
					]
				}
			}`),
			"/api/v2.0/projects/myproject/repositories/malformedrepo/artifacts/sha256:999/additions/vulnerabilities": []byte(`{
				malformed json
			}`),
		},
	}

	adaptor := NewHarborAdaptor()
	adaptor.client = mockAPI

	imageIDs := []ContainerImageIdentifier{
		{Repository: "myproject/myrepo", Hash: "sha256:123"},
		{Repository: "myproject/malformedrepo", Hash: "sha256:999"},
		{Repository: "myproject/team/backend", Hash: "sha256:nested"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), imageIDs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse vulnerability payload")

	assert.Len(t, reports, 3)
	assert.Len(t, reports[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "High", reports[0].Vulnerabilities[0].Severity)
	assert.Equal(t, "Test vulnerability", reports[0].Vulnerabilities[0].Description)

	assert.Len(t, reports[1].Vulnerabilities, 0) // Malformed should return empty
	assert.Len(t, reports[2].Vulnerabilities, 1)
	assert.Equal(t, "CVE-NESTED", reports[2].Vulnerabilities[0].ID)
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "Critical"},
		{"critical", "Critical"},
		{"HIGH", "High"},
		{"MEDIUM", "Medium"},
		{"LOW", "Low"},
		{"negligible", "Negligible"},
		{"none", "Negligible"},
		{"unknown", "Unknown"},
		{"invalid", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeSeverity(tt.input))
		})
	}
}

func TestHarborAdaptor_GetImagesInformation(t *testing.T) {
	adaptor := NewHarborAdaptor()
	adaptor.client = &mockHarborAPI{}

	infos, err := adaptor.GetImagesInformation(context.Background(), []ContainerImageIdentifier{{}})
	assert.NoError(t, err)
	assert.Len(t, infos, 1)
}

func TestHarborAdaptor_Destroy(t *testing.T) {
	adaptor := NewHarborAdaptor()
	assert.NoError(t, adaptor.Destroy())
}
