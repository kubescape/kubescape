package imagescan

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func azureLimitRows(count int) []any {
	rows := make([]any, count)
	for i := range rows {
		rows[i] = map[string]any{"id": fmt.Sprintf("CVE-%04d", i), "severity": "High"}
	}
	return rows
}

func azureLimitImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{Registry: "test.azurecr.io", Repository: "app", Hash: "sha256:123"}
}

func TestAzureFindingLimitReportsIncompleteResults(t *testing.T) {
	for _, count := range []int{999, 1000, 1001, 1005} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			calls := 0
			adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
				resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					calls++
					return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: azureLimitRows(count)}}, nil
				},
			}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
			if count > 1000 {
				require.ErrorContains(t, err, "incomplete")
				require.ErrorContains(t, err, "1000")
			} else {
				require.NoError(t, err, "exactly 1000 results on a final page is complete")
				require.Equal(t, ScanStatusScanned, reports[0].Status)
			}
			require.Len(t, reports, 1)
			require.Len(t, reports[0].Vulnerabilities, min(count, 1000))
			require.Equal(t, "CVE-0000", reports[0].Vulnerabilities[0].ID)
			require.Equal(t, fmt.Sprintf("CVE-%04d", min(count, 1000)-1), reports[0].Vulnerabilities[min(count, 1000)-1].ID)
			require.Equal(t, 1, calls)
		})
	}
}

func TestAzureFindingLimitDuringCVEExpansion(t *testing.T) {
	for _, titles := range []int{2, 3} {
		t.Run(fmt.Sprint(titles), func(t *testing.T) {
			rows := azureLimitRows(998)
			cves := make([]any, titles)
			for i := range cves {
				cves[i] = map[string]any{"title": fmt.Sprintf("CVE-expanded-%d", i)}
			}
			rows = append(rows, map[string]any{"id": "assessment", "cve": cves, "severity": "Critical"})
			adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
				resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: rows}}, nil
				},
			}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
			if titles == 3 {
				require.ErrorContains(t, err, "incomplete", "one assessment can overflow the limit through its CVE list")
			} else {
				require.NoError(t, err)
			}
			require.Len(t, reports[0].Vulnerabilities, 1000)
			require.Equal(t, "CVE-expanded-0", reports[0].Vulnerabilities[998].ID)
			require.Equal(t, "CVE-expanded-1", reports[0].Vulnerabilities[999].ID)
			require.Equal(t, "Critical", reports[0].Vulnerabilities[999].Severity)
		})
	}
}

func TestAzureFindingLimitWithContinuationToken(t *testing.T) {
	for _, firstPage := range []int{999, 1000} {
		t.Run(fmt.Sprint(firstPage), func(t *testing.T) {
			calls := 0
			adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
				resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					calls++
					if calls == 1 {
						require.Nil(t, req.Options.SkipToken)
						return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
							Data: azureLimitRows(firstPage), SkipToken: to.Ptr("second-page"),
						}}, nil
					}
					require.Equal(t, "second-page", *req.Options.SkipToken)
					return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: azureLimitRows(2)}}, nil
				},
			}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
			require.ErrorContains(t, err, "incomplete")
			require.Len(t, reports[0].Vulnerabilities, 1000)
			if firstPage == 1000 {
				require.Equal(t, 1, calls, "do not download another page after exhausting the result budget")
			} else {
				require.Equal(t, 2, calls)
			}
		})
	}
}

func TestAzureTruncationWithoutCursorIsIncomplete(t *testing.T) {
	for _, skip := range []*string{nil, to.Ptr("")} {
		for _, count := range []int{0, 1, 1000} {
			t.Run(fmt.Sprintf("rows=%d/cursor=%v", count, skip), func(t *testing.T) {
				calls := 0
				adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
					resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
						calls++
						return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
							Data: azureLimitRows(count), SkipToken: skip, ResultTruncated: to.Ptr(armresourcegraph.ResultTruncatedTrue),
						}}, nil
					},
				}}
				reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
				require.ErrorContains(t, err, "incomplete")
				require.ErrorContains(t, err, "continuation")
				require.Len(t, reports[0].Vulnerabilities, count)
				require.Equal(t, 1, calls, "a truncated empty response must not fall back to a successful discovery query")
			})
		}
	}
}

func TestAzureTruncatedPageWithCursorCanComplete(t *testing.T) {
	calls := 0
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls++
			if calls == 1 {
				return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
					Data: azureLimitRows(1), SkipToken: to.Ptr("next"), ResultTruncated: to.Ptr(armresourcegraph.ResultTruncatedTrue),
				}}, nil
			}
			require.Equal(t, "next", *req.Options.SkipToken)
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
				Data: []any{map[string]any{"id": "CVE-final"}}, ResultTruncated: to.Ptr(armresourcegraph.ResultTruncatedFalse),
			}}, nil
		},
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
	require.NoError(t, err)
	require.Len(t, reports[0].Vulnerabilities, 2)
	require.Equal(t, "CVE-final", reports[0].Vulnerabilities[1].ID)
	require.Equal(t, 2, calls)
}

func TestAzureLimitKeepsOtherImages(t *testing.T) {
	calls := 0
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls++
			count := 1001
			if calls == 2 {
				count = 1
			}
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: azureLimitRows(count)}}, nil
		},
	}}
	images := []ContainerImageIdentifier{azureLimitImage(), azureLimitImage()}
	images[1].Hash = "sha256:other"
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports, 2)
	require.Equal(t, images[0], reports[0].ImageID)
	require.Equal(t, images[1], reports[1].ImageID)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Len(t, reports[1].Vulnerabilities, 1)
	require.Equal(t, ScanStatusScanned, reports[1].Status)
}

func TestAzureLimitRetainsEarlierPagesOnProviderFailure(t *testing.T) {
	failed := errors.New("next page failed")
	calls := 0
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls++
			if calls == 1 {
				return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: azureLimitRows(999), SkipToken: to.Ptr("next")}}, nil
			}
			return armresourcegraph.ClientResourcesResponse{}, failed
		},
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 999)
	require.NotContains(t, err.Error(), "limit", "do not replace an API error with an unproven limit error")
}

func TestAzureLimitDoesNotHideCursorValidationErrors(t *testing.T) {
	for _, token := range []string{" ", "\t"} {
		t.Run(fmt.Sprintf("token=%q", token), func(t *testing.T) {
			adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
				resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
						Data: azureLimitRows(1000), SkipToken: to.Ptr(token),
					}}, nil
				},
			}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
			require.ErrorContains(t, err, "blank skip token")
			require.Len(t, reports[0].Vulnerabilities, 1000)
		})
	}
}

func TestAzureLimitAndOtherImageErrorsAreBothReturned(t *testing.T) {
	failed := errors.New("another image query failed")
	calls := 0
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls++
			if calls == 1 {
				return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: azureLimitRows(1001)}}, nil
			}
			return armresourcegraph.ClientResourcesResponse{}, failed
		},
	}}
	images := []ContainerImageIdentifier{azureLimitImage(), azureLimitImage()}
	images[1].Repository = "another"
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorIs(t, err, failed)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports, 2)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Empty(t, reports[1].Vulnerabilities)
	require.Equal(t, images[1], reports[1].ImageID)
}

func TestAzureSubLimitPageCanFinishWithEmptyContinuation(t *testing.T) {
	calls := 0
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls++
			if calls == 1 {
				return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
					Data: azureLimitRows(999), SkipToken: to.Ptr("next"),
				}}, nil
			}
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: []any{}}}, nil
		},
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
	require.NoError(t, err)
	require.Len(t, reports[0].Vulnerabilities, 999)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Equal(t, 2, calls)
}

func TestAzureExplicitCompleteResponseAtLimit(t *testing.T) {
	adaptor := &AzureAdaptor{registryHost: "test.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
				Data: azureLimitRows(1000), SkipToken: to.Ptr(""),
				ResultTruncated: to.Ptr(armresourcegraph.ResultTruncatedFalse),
			}}, nil
		},
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{azureLimitImage()})
	require.NoError(t, err, "the provider's explicit final response must remain successful at the exact budget")
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Equal(t, "CVE-0000", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-0999", reports[0].Vulnerabilities[999].ID)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}
