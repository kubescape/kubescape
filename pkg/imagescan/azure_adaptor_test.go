package imagescan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAzureClient struct {
	resourcesOut func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)
}

func (m *mockAzureClient) Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	if m.resourcesOut != nil {
		return m.resourcesOut(query)
	}
	return armresourcegraph.ClientResourcesResponse{}, nil
}

func TestAzureAdaptor_Login_Success(t *testing.T) {
	adaptor := NewAzureAdaptor()

	adaptor.credProvider = func(options *azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return nil, nil // mock credential
	}
	adaptor.clientFactory = func(cred azcore.TokenCredential, options *arm.ClientOptions) (AzureAPI, error) {
		return &mockAzureClient{}, nil
	}

	err := adaptor.Login(context.Background(), "test.azurecr.io", RegistryCredentials{})
	assert.NoError(t, err)
	assert.NotNil(t, adaptor.client)
}

func TestAzureAdaptor_Login_ExplicitCreds(t *testing.T) {
	adaptor := NewAzureAdaptor()
	err := adaptor.Login(context.Background(), "test.azurecr.io", RegistryCredentials{Username: "foo"})
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")
}

func TestAzureAdaptor_resolveAzureCloudConfig(t *testing.T) {
	_, err := resolveAzureCloudConfig("test.docker.io")
	assert.ErrorContains(t, err, "invalid Azure registry format")

	_, err = resolveAzureCloudConfig("test.azurecr.us")
	assert.NoError(t, err)

	_, err = resolveAzureCloudConfig("MyRegistry.azurecr.io")
	assert.NoError(t, err)

	// Azure Germany (.azurecr.de) was retired in October 2021 and is
	// intentionally not supported.
	_, err = resolveAzureCloudConfig("test.azurecr.de")
	assert.ErrorContains(t, err, "invalid Azure registry format")
}

func TestNewDefaultAzureCredential(t *testing.T) {
	cred, err := newDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{Cloud: cloud.AzurePublic},
	})
	require.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestAzureAdaptor_KQLValidation(t *testing.T) {
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"

	// Mixed-case validation test
	err := adaptor.validateImageID(ContainerImageIdentifier{Registry: "Test.AzureCR.io", Repository: "repo", Hash: "sha256:123"})
	assert.NoError(t, err)

	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "wrong.azurecr.io", Repository: "repo", Hash: "sha256:123"})
	assert.ErrorContains(t, err, "does not match logged-in registry")

	// KQL breakout injection test
	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "test.azurecr.io", Repository: "repo\" or 1=1", Hash: "sha256:123"})
	assert.ErrorContains(t, err, "invalid characters")

	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "test.azurecr.io", Repository: "repo", Hash: "$()"})
	assert.ErrorContains(t, err, "invalid characters")
}

func TestAzureAdaptor_GetImagesInformation_Guards(t *testing.T) {
	adaptor := NewAzureAdaptor()
	_, err := adaptor.GetImagesInformation(context.Background(), nil)
	assert.ErrorContains(t, err, "azure client not initialized")
}

func TestAzureAdaptor_NormalizeSeverity(t *testing.T) {
	assert.Equal(t, "Critical", NormalizeSeverity("Critical"))
	assert.Equal(t, "High", NormalizeSeverity("High"))
	assert.Equal(t, "Medium", NormalizeSeverity("Medium"))
	assert.Equal(t, "Low", NormalizeSeverity("Low"))
	assert.Equal(t, "Negligible", NormalizeSeverity("Informational"))
	assert.Equal(t, "Unknown", NormalizeSeverity("SomethingElse"))
}

func TestAzureAdaptor_GetImagesScanStatus(t *testing.T) {
	tests := []struct {
		name          string
		mockFunc      func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)
		images        []ContainerImageIdentifier
		expectedScan  bool
		expectedError bool
	}{
		{
			name: "scan complete with timeGenerated",
			mockFunc: func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](1),
						Data: []interface{}{
							map[string]interface{}{
								"timeGenerated": "2023-01-01T12:00:00Z",
							},
						},
					},
				}, nil
			},
			expectedScan: true,
		},
		{
			name: "scan pending or no data",
			mockFunc: func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](0),
					},
				}, nil
			},
			expectedScan: false,
		},
		{
			name: "arg api error path",
			mockFunc: func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("arg failed")
			},
			expectedError: true,
		},
		{
			name: "invalid identifier (validation error)",
			mockFunc: func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				t.Fatalf("API should not be called for invalid identifier")
				return armresourcegraph.ClientResourcesResponse{}, nil
			},
			images: []ContainerImageIdentifier{
				{Registry: "test.azurecr.io", Repository: "invalid'repo", Hash: "sha256:1234"},
			},
			expectedError: true,
		},
		{
			name: "mixed valid and invalid identifiers",
			mockFunc: func(t *testing.T, req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				assert.Contains(t, *req.Query, "sha256:valid")
				assert.NotContains(t, *req.Query, "sha256:invalid")
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](1),
						Data: []interface{}{
							map[string]interface{}{
								"timeGenerated": "2023-01-01T12:00:00Z",
							},
						},
					},
				}, nil
			},
			images: []ContainerImageIdentifier{
				{Registry: "test.azurecr.io", Repository: "invalid'repo", Hash: "sha256:invalid"},
				{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:valid"},
			},
			expectedError: true,
			expectedScan:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewAzureAdaptor()
			adaptor.registryHost = "test.azurecr.io"
			adaptor.client = &mockAzureClient{
				resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					return tt.mockFunc(t, req)
				},
			}

			images := tt.images
			if images == nil {
				images = []ContainerImageIdentifier{
					{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
				}
			}

			statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Len(t, statuses, len(images))
				if tt.name == "mixed valid and invalid identifiers" {
					assert.False(t, statuses[0].IsScanAvailable, "invalid identifier should result in failed scan status")
					assert.True(t, statuses[1].IsScanAvailable, "valid identifier should process successfully")
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, statuses, len(images))
				assert.Equal(t, tt.expectedScan, statuses[0].IsScanAvailable)
				if tt.name == "scan complete with timeGenerated" {
					expectedTime, _ := time.Parse(time.RFC3339Nano, "2023-01-01T12:00:00Z")
					assert.Equal(t, expectedTime, statuses[0].LastScanDate)
				}
			}
		})
	}
}

func TestAzureAdaptor_GetImagesVulnerabilities_ValidationErrors(t *testing.T) {
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"

	apiCalled := false
	adaptor.client = &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			apiCalled = true
			assert.Contains(t, *req.Query, "test-repo")
			assert.NotContains(t, *req.Query, "invalid'repo")
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{
					Data: []interface{}{
						map[string]interface{}{
							"id":          "vuln1",
							"severity":    "High",
							"description": "Test vuln 1",
						},
					},
				},
			}, nil
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "invalid'repo", Hash: "sha256:1234"},
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.Error(t, err)
	assert.Len(t, reports, 2)
	assert.True(t, apiCalled, "API should have been called for the valid identifier")

	// First report should be empty due to validation error
	assert.Empty(t, reports[0].Vulnerabilities)

	// Second report should contain the vulnerability from the API
	assert.Len(t, reports[1].Vulnerabilities, 1)
	assert.Equal(t, "vuln1", reports[1].Vulnerabilities[0].ID)
}

func TestAzureAdaptor_GetImagesVulnerabilities_PaginationAndCVE(t *testing.T) {
	callCount := 0

	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"
	adaptor.client = &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			callCount++
			if callCount == 1 {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						Data: []interface{}{
							map[string]interface{}{
								"id":          "vuln1",
								"severity":    "High",
								"description": "Test vuln 1",
								"cve": []interface{}{
									map[string]interface{}{"title": "CVE-2023-1111"},
									map[string]interface{}{"title": "CVE-2023-2222"},
								},
							},
						},
						SkipToken: to.Ptr("token"),
					},
				}, nil
			}
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{
					Data: []interface{}{
						map[string]interface{}{
							"id":          "vuln2",
							"severity":    "Medium",
							"description": "Test vuln 2",
						},
					},
					SkipToken: nil,
				},
			}, nil
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 3)
	assert.Equal(t, 2, callCount) // Ensure pagination looped exactly twice

	vuln1 := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1111", vuln1.ID) // Primary CVE extracted
	assert.Equal(t, "High", vuln1.Severity)

	vuln2 := reports[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-2222", vuln2.ID) // Second CVE extracted
	assert.Equal(t, "High", vuln2.Severity)

	vuln3 := reports[0].Vulnerabilities[2]
	assert.Equal(t, "vuln2", vuln3.ID) // Fallback to ID
}

func TestAzureAdaptor_GetImagesVulnerabilities_Cap(t *testing.T) {
	// Test that >1000 items truncates instead of failing hard
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"
	adaptor.client = &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			data := make([]interface{}, 1005)
			for i := 0; i < 1005; i++ {
				data[i] = map[string]interface{}{"id": fmt.Sprintf("vuln%d", i)}
			}
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{Data: data},
			}, nil
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1000) // Truncated cleanly
}

func TestNextAzureVulnerabilityToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		skipToken    *string
		seen         map[string]struct{}
		pagesFetched int
		wantToken    string
		wantNext     bool
		wantError    string
	}{
		{
			name:         "nil token completes pagination",
			seen:         map[string]struct{}{},
			pagesFetched: 1,
		},
		{
			name:         "empty token completes pagination",
			skipToken:    to.Ptr(""),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
		},
		{
			name:         "new token advances pagination",
			skipToken:    to.Ptr("page-two"),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantToken:    "page-two",
			wantNext:     true,
		},
		{ //nolint:gosec // opaque pagination cursor fixture, not a credential
			name:         "opaque token is not normalized",
			skipToken:    to.Ptr(" token-with-space "),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantToken:    " token-with-space ",
			wantNext:     true,
		},
		{
			name:         "blank token is malformed",
			skipToken:    to.Ptr(" \t "),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantError:    "blank skip token",
		},
		{
			name:         "immediate repeat is rejected",
			skipToken:    to.Ptr("page-two"),
			seen:         map[string]struct{}{"page-two": {}},
			pagesFetched: 2,
			wantError:    `repeated skip token "page-two"`,
		},
		{
			name:         "cycle to old token is rejected",
			skipToken:    to.Ptr("page-two"),
			seen:         map[string]struct{}{"page-two": {}, "page-three": {}},
			pagesFetched: 3,
			wantError:    `repeated skip token "page-two"`,
		},
		{
			name:         "last allowed page may complete",
			seen:         map[string]struct{}{},
			pagesFetched: maxAzureVulnerabilityPages,
		},
		{
			name:         "last allowed page may not continue",
			skipToken:    to.Ptr("too-many"),
			seen:         map[string]struct{}{},
			pagesFetched: maxAzureVulnerabilityPages,
			wantError:    "exceeded max pages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			before := len(tt.seen)
			token, hasNext, err := nextAzureVulnerabilityToken(tt.skipToken, tt.seen, tt.pagesFetched)

			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				assert.Empty(t, token)
				assert.False(t, hasNext)
				assert.Len(t, tt.seen, before)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
			assert.Equal(t, tt.wantNext, hasNext)
			if tt.wantNext {
				assert.Contains(t, tt.seen, tt.wantToken)
			} else {
				assert.Len(t, tt.seen, before)
			}
		})
	}
}

func TestAzureAdaptorPaginationStopsOnImmediateTokenRepeat(t *testing.T) {
	t.Parallel()

	callCount := 0
	requestedTokens := []string{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		callCount++
		requestedTokens = append(requestedTokens, azureRequestSkipToken(req))
		return azureVulnerabilityPage("stalled", fmt.Sprintf("CVE-%d", callCount)), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("stalled-repository"),
	})

	require.ErrorContains(t, err, `repeated skip token "stalled"`)
	assert.Equal(t, 2, callCount, "the repeated token must stop a third network request")
	assert.Equal(t, []string{"", "stalled"}, requestedTokens)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-1", "CVE-2"}, vulnerabilityIDs(reports[0]))
}

func TestAzureAdaptorPaginationStopsOnTokenCycle(t *testing.T) {
	t.Parallel()

	pages := []armresourcegraph.ClientResourcesResponse{
		azureVulnerabilityPage("cursor-a", "CVE-FIRST"),
		azureVulnerabilityPage("cursor-b", "CVE-SECOND"),
		azureVulnerabilityPage("cursor-a", "CVE-THIRD"),
	}
	requests := []string{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		requests = append(requests, azureRequestSkipToken(req))
		return pages[len(requests)-1], nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("cyclic-repository"),
	})

	require.ErrorContains(t, err, `repeated skip token "cursor-a"`)
	assert.Equal(t, []string{"", "cursor-a", "cursor-b"}, requests)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FIRST", "CVE-SECOND", "CVE-THIRD"}, vulnerabilityIDs(reports[0]))
}

func TestAzureAdaptorPaginationRejectsBlankToken(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := newAzurePaginationTestAdaptor(func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		callCount++
		return azureVulnerabilityPage("  ", "CVE-PARTIAL"), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("blank-token"),
	})

	require.ErrorContains(t, err, "blank skip token")
	assert.Equal(t, 1, callCount)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-PARTIAL"}, vulnerabilityIDs(reports[0]))
}

func TestAzureAdaptorPaginationTreatsEmptyTokenAsCompletion(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := newAzurePaginationTestAdaptor(func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		callCount++
		return azureVulnerabilityPage("", "CVE-FINAL"), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("empty-token"),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FINAL"}, vulnerabilityIDs(reports[0]))
}

func TestAzureAdaptorPaginationUsesEveryDistinctTokenOnce(t *testing.T) {
	t.Parallel()

	pages := map[string]armresourcegraph.ClientResourcesResponse{
		"":       azureVulnerabilityPage("second", "CVE-FIRST"),
		"second": azureVulnerabilityPage("third", "CVE-SECOND"),
		"third":  azureFinalVulnerabilityPage("CVE-THIRD"),
	}
	requests := []string{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		token := azureRequestSkipToken(req)
		requests = append(requests, token)
		page, ok := pages[token]
		if !ok {
			return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("unexpected token %q", token)
		}
		return page, nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("healthy"),
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"", "second", "third"}, requests)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FIRST", "CVE-SECOND", "CVE-THIRD"}, vulnerabilityIDs(reports[0]))
}

func TestAzureAdaptorPaginationKeepsOtherImageResults(t *testing.T) {
	t.Parallel()

	callsByRepository := map[string]int{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		query := toValue(req.Query)
		repository := "healthy"
		if strings.Contains(query, `repositoryName == "stalled"`) {
			repository = "stalled"
		}
		callsByRepository[repository]++
		if repository == "healthy" {
			return azureFinalVulnerabilityPage("CVE-HEALTHY"), nil
		}
		return azureVulnerabilityPage("same", fmt.Sprintf("CVE-STALL-%d", callsByRepository[repository])), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("healthy"),
		azureTestImage("stalled"),
	})

	require.ErrorContains(t, err, "repeated skip token")
	require.Len(t, reports, 2)
	assert.Equal(t, []string{"CVE-HEALTHY"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, []string{"CVE-STALL-1", "CVE-STALL-2"}, vulnerabilityIDs(reports[1]))
	assert.Equal(t, map[string]int{"healthy": 1, "stalled": 2}, callsByRepository)
}

func TestAzureAdaptorPaginationKeepsPartialDataOnAPIFailure(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := newAzurePaginationTestAdaptor(func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		callCount++
		if callCount == 1 {
			return azureVulnerabilityPage("second", "CVE-FIRST"), nil
		}
		return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("temporary ARG failure")
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("partial"),
	})

	require.ErrorContains(t, err, "temporary ARG failure")
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FIRST"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, 2, callCount)
}

func TestAzureAdaptorPaginationCursorStateIsScopedPerImage(t *testing.T) {
	t.Parallel()

	callsByRepository := map[string]int{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		query := toValue(req.Query)
		repository := "first"
		if strings.Contains(query, `repositoryName == "second"`) {
			repository = "second"
		}
		callsByRepository[repository]++
		if req.Options.SkipToken == nil {
			return azureVulnerabilityPage("shared-token", repository+"-first"), nil
		}
		assert.Equal(t, "shared-token", *req.Options.SkipToken)
		return azureFinalVulnerabilityPage(repository + "-second"), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("first"),
		azureTestImage("second"),
	})

	require.NoError(t, err)
	require.Len(t, reports, 2)
	assert.Equal(t, []string{"first-first", "first-second"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, []string{"second-first", "second-second"}, vulnerabilityIDs(reports[1]))
	assert.Equal(t, map[string]int{"first": 2, "second": 2}, callsByRepository)
}

func TestAzureAdaptorPaginationAdvancesAcrossEmptyDataPages(t *testing.T) {
	t.Parallel()

	requests := []string{}
	adaptor := newAzurePaginationTestAdaptor(func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		token := azureRequestSkipToken(req)
		requests = append(requests, token)
		if token == "" {
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{SkipToken: to.Ptr("after-empty")},
			}, nil
		}
		return azureFinalVulnerabilityPage("CVE-AFTER-EMPTY"), nil
	})

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		azureTestImage("sparse"),
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"", "after-empty"}, requests)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-AFTER-EMPTY"}, vulnerabilityIDs(reports[0]))
}

func newAzurePaginationTestAdaptor(fetch func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)) *AzureAdaptor {
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"
	adaptor.client = &mockAzureClient{resourcesOut: fetch}
	return adaptor
}

func azureTestImage(repository string) ContainerImageIdentifier {
	return ContainerImageIdentifier{
		Registry:   "test.azurecr.io",
		Repository: repository,
		Hash:       "sha256:1234",
	}
}

func azureVulnerabilityPage(skipToken, vulnerabilityID string) armresourcegraph.ClientResourcesResponse {
	return armresourcegraph.ClientResourcesResponse{
		QueryResponse: armresourcegraph.QueryResponse{
			Data: []interface{}{
				map[string]interface{}{
					"id":          vulnerabilityID,
					"severity":    "High",
					"description": "fixture vulnerability",
				},
			},
			SkipToken: to.Ptr(skipToken),
		},
	}
}

func azureFinalVulnerabilityPage(vulnerabilityID string) armresourcegraph.ClientResourcesResponse {
	page := azureVulnerabilityPage("unused", vulnerabilityID)
	page.SkipToken = nil
	return page
}

func azureRequestSkipToken(req armresourcegraph.QueryRequest) string {
	if req.Options == nil || req.Options.SkipToken == nil {
		return ""
	}
	return *req.Options.SkipToken
}

func toValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// --- newACRKeychain / azureACRKeychain ---

type stubTokenCredential struct {
	token     azcore.AccessToken
	err       error
	calls     int
	gotScopes []string
}

func (s *stubTokenCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	s.calls++
	s.gotScopes = opts.Scopes
	if s.err != nil {
		return azcore.AccessToken{}, s.err
	}
	return s.token, nil
}

// fakeJWT builds a JWT-shaped (but unsigned) string with the given payload
// claims, matching the format tenantIDFromToken parses.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".signature"
}

// newRedirectingClient returns an *http.Client whose connections are
// transparently redirected to target regardless of the requested host,
// skipping TLS verification. It lets tests exercise the real
// "https://<registry>/..." URL construction in exchangeForACRRefreshToken
// against a local httptest server, even though that server's certificate
// isn't valid for the requested (fake ACR) hostname.
func newRedirectingClient(target string) *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, target)
			},
			//nolint:gosec // test-only client talking to a local httptest server
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func TestACRKeychainResolveNonACRRegistryIsAnonymousWithoutTouchingAzure(t *testing.T) {
	credCalled := false
	k := &azureACRKeychain{
		httpClient: http.DefaultClient,
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			credCalled = true
			return nil, errors.New("should not be called")
		},
	}

	auth, err := k.Resolve(stubResource{registry: "docker.io"})
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
	assert.False(t, credCalled, "should not attempt Azure auth for a non-ACR registry")
}

func TestACRKeychainResolveSoftFailsToAnonymousWhenCredentialUnavailable(t *testing.T) {
	k := &azureACRKeychain{
		httpClient: http.DefaultClient,
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			return nil, errors.New("no azure credential in this environment")
		},
	}

	auth, err := k.Resolve(stubResource{registry: "myregistry.azurecr.io"})
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth, "should fall back to Anonymous, not error, so MultiKeychain can try the next keychain")
}

func TestACRKeychainResolveSuccessReturnsIdentityTokenAuthenticator(t *testing.T) {
	token := fakeJWT(t, map[string]any{"tid": "11111111-1111-1111-1111-111111111111"})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "myregistry.azurecr.io", r.PostForm.Get("service"))
		assert.Equal(t, token, r.PostForm.Get("access_token"))
		assert.Equal(t, "11111111-1111-1111-1111-111111111111", r.PostForm.Get("tenant"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh-token"}`))
	}))
	defer server.Close()

	stubCred := &stubTokenCredential{token: azcore.AccessToken{Token: token, ExpiresOn: time.Now().Add(time.Hour)}}
	k := &azureACRKeychain{
		httpClient: newRedirectingClient(server.Listener.Addr().String()),
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			return stubCred, nil
		},
	}

	authenticator, err := k.Resolve(stubResource{registry: "myregistry.azurecr.io"})
	require.NoError(t, err)
	require.NotEqual(t, authn.Anonymous, authenticator)

	cfg, err := authenticator.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "acr-refresh-token", cfg.IdentityToken)

	require.Len(t, stubCred.gotScopes, 1)
	// azure-sdk-for-go's own arm/runtime/pipeline.go builds ARM token scopes
	// as conf.Audience+"/.default", and conf.Audience already ends in "/"
	// (see arm/runtime/runtime.go's init()) - the double slash below is
	// what every ARM client in the SDK actually sends, not a bug here.
	assert.Equal(t, "https://management.core.windows.net//.default", stubCred.gotScopes[0])
}

func TestACRKeychainUsesSovereignCloudAudience(t *testing.T) {
	tests := []struct {
		registry     string
		wantAudience string
	}{
		{"myregistry.azurecr.io", "https://management.core.windows.net//.default"},
		{"myregistry.azurecr.cn", "https://management.core.chinacloudapi.cn//.default"},
		{"myregistry.azurecr.us", "https://management.core.usgovcloudapi.net//.default"},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh-token"}`))
			}))
			defer server.Close()

			stubCred := &stubTokenCredential{token: azcore.AccessToken{Token: "aad-access-token", ExpiresOn: time.Now().Add(time.Hour)}}
			k := &azureACRKeychain{
				httpClient: newRedirectingClient(server.Listener.Addr().String()),
				credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
					return stubCred, nil
				},
			}

			_, err := k.Resolve(stubResource{registry: tt.registry})
			require.NoError(t, err)
			require.Len(t, stubCred.gotScopes, 1)
			assert.Equal(t, tt.wantAudience, stubCred.gotScopes[0])
		})
	}
}

func TestACRKeychainAcrIdentityTokenErrorsWhenAADTokenAcquisitionFails(t *testing.T) {
	stubCred := &stubTokenCredential{err: errors.New("aad unavailable")}
	k := &azureACRKeychain{
		httpClient: http.DefaultClient,
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			return stubCred, nil
		},
	}

	_, err := k.acrIdentityToken(context.Background(), "myregistry.azurecr.io", cloud.AzurePublic)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire Azure AD access token")
}

func TestACRKeychainAcrIdentityTokenErrorsWhenNoARMAudienceConfigured(t *testing.T) {
	k := &azureACRKeychain{
		httpClient: http.DefaultClient,
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			return &stubTokenCredential{}, nil
		},
	}

	_, err := k.acrIdentityToken(context.Background(), "myregistry.azurecr.io", cloud.Configuration{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Azure Resource Manager audience configured")
}

func TestACRKeychainExchangeErrorsOnNonOKStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer server.Close()

	k := &azureACRKeychain{httpClient: server.Client()}
	_, err := k.exchangeForACRRefreshToken(context.Background(), server.Listener.Addr().String(), "aad-access-token", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestACRKeychainExchangeErrorsOnEmptyRefreshToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	k := &azureACRKeychain{httpClient: server.Client()}
	_, err := k.exchangeForACRRefreshToken(context.Background(), server.Listener.Addr().String(), "aad-access-token", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no refresh token")
}

func TestACRKeychainExchangeErrorsOnMalformedJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	k := &azureACRKeychain{httpClient: server.Client()}
	_, err := k.exchangeForACRRefreshToken(context.Background(), server.Listener.Addr().String(), "aad-access-token", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestACRKeychainExchangeErrorsOnNetworkFailure(t *testing.T) {
	k := &azureACRKeychain{httpClient: &http.Client{Timeout: 2 * time.Second}}
	_, err := k.exchangeForACRRefreshToken(context.Background(), "127.0.0.1:1", "aad-access-token", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to reach ACR token exchange endpoint")
}

func TestACRKeychainExchangeErrorsOnInvalidRegistryURL(t *testing.T) {
	k := &azureACRKeychain{httpClient: http.DefaultClient}
	_, err := k.exchangeForACRRefreshToken(context.Background(), "bad host\n", "aad-access-token", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build ACR token exchange request")
}

func TestACRKeychainExchangeOmitsTenantWhenEmpty(t *testing.T) {
	var sawTenantParam bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		_, sawTenantParam = r.PostForm["tenant"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh-token"}`))
	}))
	defer server.Close()

	k := &azureACRKeychain{httpClient: server.Client()}
	_, err := k.exchangeForACRRefreshToken(context.Background(), server.Listener.Addr().String(), "aad-access-token", "")
	require.NoError(t, err)
	assert.False(t, sawTenantParam)
}

// --- tenantIDFromToken ---

func TestTenantIDFromToken(t *testing.T) {
	token := fakeJWT(t, map[string]any{"tid": "22222222-2222-2222-2222-222222222222", "aud": "https://management.azure.com/"})
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", tenantIDFromToken(token))
}

func TestTenantIDFromTokenHandlesMalformedInput(t *testing.T) {
	assert.Empty(t, tenantIDFromToken("not-a-jwt"))
	assert.Empty(t, tenantIDFromToken("only.two"))
	assert.Empty(t, tenantIDFromToken("one.two.three.four"))
	assert.Empty(t, tenantIDFromToken("header.not-valid-base64!!!.sig"))
	assert.Empty(t, tenantIDFromToken(fakeJWT(t, map[string]any{"aud": "no-tid-claim"})))

	// Valid base64, but the decoded bytes aren't JSON at all.
	notJSONPayload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	assert.Empty(t, tenantIDFromToken("header."+notJSONPayload+".sig"))
}

// --- end-to-end: a real go-containerregistry pull authenticated through the
// Azure keychain ---
//
// Every other test above checks that Resolve() returns the right
// authn.Authenticator in isolation. This one instead plugs that authenticator
// into a real remote.Get call against a fake OCI Distribution registry that
// enforces the exact challenge/token flow ACR uses, proving the full chain
// actually works together end to end: WWW-Authenticate Bearer challenge on
// /v2/ -> our ACR /oauth2/exchange call -> IdentityToken handed to
// go-containerregistry -> its own OAuth2 refresh_token grant against
// /oauth2/token -> a Bearer-authenticated manifest pull. It also exercises
// newRegistryKeychain's real composition (authn.DefaultKeychain checked
// first, falling through to the Azure keychain), not just the Azure piece in
// isolation.
func TestACRKeychainAuthenticatesARealRegistryPull(t *testing.T) {
	const registryHost = "myregistry.azurecr.io"
	const repo = "team/app"
	const tag = "v1"
	const bearerToken = "bearer-access-token" // #nosec G101 -- test fixture, not a credential
	const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},"layers":[]}`

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/oauth2/token",service=%q`, registryHost, registryHost))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/oauth2/exchange", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "access_token", r.PostForm.Get("grant_type"))
		assert.Equal(t, registryHost, r.PostForm.Get("service"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh-token"}`))
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.PostForm.Get("grant_type"))
		assert.Equal(t, "acr-refresh-token", r.PostForm.Get("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + bearerToken + `"}`))
	})
	mux.HandleFunc("/v2/"+repo+"/manifests/"+tag, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearerToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write([]byte(manifest))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	redirectingClient := newRedirectingClient(server.Listener.Addr().String())

	stubCred := &stubTokenCredential{token: azcore.AccessToken{Token: "aad-access-token", ExpiresOn: time.Now().Add(time.Hour)}}
	azureKC := &azureACRKeychain{
		httpClient: redirectingClient,
		credProvider: func(cloud.Configuration) (azcore.TokenCredential, error) {
			return stubCred, nil
		},
	}
	// Mirrors newRegistryKeychain's real composition (authn.DefaultKeychain,
	// then the Azure keychain) rather than using the Azure piece bare - proves
	// the actual production keychain shape, not just its Azure half.
	kc := authn.NewMultiKeychain(authn.DefaultKeychain, azureKC)

	ref, err := name.ParseReference(registryHost + "/" + repo + ":" + tag)
	require.NoError(t, err)

	desc, err := remote.Get(ref,
		remote.WithAuthFromKeychain(kc),
		remote.WithTransport(redirectingClient.Transport),
	)
	require.NoError(t, err)
	assert.Equal(t, 1, stubCred.calls, "the AAD token should be fetched once and then reused for the manifest pull")
	assert.NotEmpty(t, desc.Manifest)
}
