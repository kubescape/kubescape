package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func TestAzureFreshness_StatusQueryMustSelectNewestAssessment(t *testing.T) {
	var query string
	a := &AzureAdaptor{registryHost: "registry.azurecr.io", client: &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		query = *req.Query
		date := "2022-01-01T00:00:00Z"
		if strings.Contains(query, "order by timeGenerated desc") {
			date = "2026-10-14T00:00:00Z"
		}
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{TotalRecords: to.Ptr[int64](1), Data: []interface{}{map[string]interface{}{"timeGenerated": date}}}}, nil
	}}}
	image := ContainerImageIdentifier{Registry: "registry.azurecr.io", Repository: "team/app", Hash: "sha256:123"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Contains(t, query, "order by timeGenerated desc")
	require.Equal(t, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), statuses[0].LastScanDate)
}

// freshnessAzureAPI models the query's selection contract over deliberately
// unsorted assessment rows. It is not a live Resource Graph emulator.
type freshnessAzureAPI struct {
	dates    []string
	queries  []armresourcegraph.QueryRequest
	failure  error
	response *armresourcegraph.ClientResourcesResponse
}

func (api *freshnessAzureAPI) Resources(ctx context.Context, req armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	api.queries = append(api.queries, req)
	if ctx.Err() != nil {
		return armresourcegraph.ClientResourcesResponse{}, ctx.Err()
	}
	if api.failure != nil {
		return armresourcegraph.ClientResourcesResponse{}, api.failure
	}
	if api.response != nil {
		return *api.response, nil
	}
	dates := append([]string(nil), api.dates...)
	if strings.Contains(*req.Query, "order by timeGenerated desc") {
		sort.SliceStable(dates, func(i, j int) bool {
			a, aErr := time.Parse(time.RFC3339Nano, dates[i])
			b, bErr := time.Parse(time.RFC3339Nano, dates[j])
			if aErr != nil {
				return false
			}
			return bErr != nil || a.After(b)
		})
	}
	res := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{TotalRecords: to.Ptr(int64(len(dates)))}}
	if len(dates) > 0 {
		res.Data = []interface{}{map[string]interface{}{"timeGenerated": dates[0]}}
	}
	return res, nil
}

func freshnessAzureAdaptor(api AzureAPI) *AzureAdaptor {
	return &AzureAdaptor{registryHost: "registry.azurecr.io", client: api}
}

func freshnessAzureImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{Registry: "registry.azurecr.io", Repository: "team/app", Hash: "sha256:123"}
}

func TestAzureFreshness_AllProviderOrdersSelectSameNewestDate(t *testing.T) {
	old := "2022-01-01T00:00:00Z"
	middle := "2025-01-01T00:00:00Z"
	newest := "2026-10-14T00:00:00Z"
	orders := [][]string{
		{old, middle, newest},
		{old, newest, middle},
		{middle, old, newest},
		{middle, newest, old},
		{newest, old, middle},
		{newest, middle, old},
	}
	for i, dates := range orders {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			api := &freshnessAzureAPI{dates: dates}
			statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
			require.NoError(t, err)
			require.True(t, statuses[0].IsScanAvailable)
			require.Equal(t, ScanStatusScanned, statuses[0].Status)
			require.Equal(t, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), statuses[0].LastScanDate)
			require.Len(t, api.queries, 1)
		})
	}
}

func TestAzureFreshness_QueryConvertsDynamicTimestampBeforeOrdering(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
	_, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	query := *api.queries[0].Query
	conversion := strings.Index(query, "timeGenerated = todatetime(properties.timeGenerated)")
	ordering := strings.Index(query, "order by timeGenerated desc nulls last")
	limit := strings.Index(query, "limit 1")
	require.GreaterOrEqual(t, conversion, 0)
	require.Greater(t, ordering, conversion)
	require.Greater(t, limit, ordering)
	require.NotContains(t, query, "summarize", "empty input must not become an aggregate result row")
}

func TestAzureFreshness_QueryKeepsImageScopeBeforeSelection(t *testing.T) {
	api := &freshnessAzureAPI{}
	image := freshnessAzureImage()
	image.Repository = "nested/team/app"
	image.Hash = "sha256:abcdef012345"
	_, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	query := *api.queries[0].Query
	require.Contains(t, query, `type == "microsoft.security/assessments"`)
	require.Contains(t, query, `registryName =~ "registry"`)
	require.Contains(t, query, `properties.resourceDetails.id contains "sha256:abcdef012345"`)
	require.Less(t, strings.Index(query, "| where properties.resourceDetails"), strings.Index(query, "| order by"))
	require.Equal(t, armresourcegraph.ResultFormatObjectArray, *api.queries[0].Options.ResultFormat)
}

func TestAzureFreshness_ChronologicalOrderIsNotLexicalOrder(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{
		"2026-10-14T02:00:00+02:00",
		"2026-10-14T00:30:00Z",
	}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 10, 14, 0, 30, 0, 0, time.UTC), statuses[0].LastScanDate)
	require.Contains(t, *api.queries[0].Query, "todatetime", "offsets need datetime, not string ordering")
}

func TestAzureFreshness_NanosecondDifferencesRemainVisible(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{
		"2026-10-14T00:00:00.123456788Z",
		"2026-10-14T00:00:00.123456789Z",
	}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Equal(t, 123456789, statuses[0].LastScanDate.Nanosecond())
	require.Equal(t, freshnessAzureImage(), statuses[0].ImageID)
}

func TestAzureFreshness_InvalidDatesCannotHideValidNewestDate(t *testing.T) {
	for _, invalid := range []string{"", "not-a-date", "2026-99-99T00:00:00Z", "10000-01-01T00:00:00Z"} {
		t.Run(invalid, func(t *testing.T) {
			api := &freshnessAzureAPI{dates: []string{invalid, "2025-01-01T00:00:00Z", "2026-10-14T00:00:00Z"}}
			statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
			require.NoError(t, err)
			require.True(t, statuses[0].IsScanAvailable)
			require.Equal(t, 2026, statuses[0].LastScanDate.Year())
			require.Contains(t, *api.queries[0].Query, "nulls last")
		})
	}
}

func TestAzureFreshness_AllInvalidDatesDoNotInventLastScanDate(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"invalid", ""}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.True(t, statuses[0].IsScanAvailable)
	require.Equal(t, ScanStatusScanned, statuses[0].Status)
	require.True(t, statuses[0].LastScanDate.IsZero())
	require.False(t, statuses[0].IsBomAvailable)
}

func TestAzureFreshness_NoAssessmentsRemainUnavailable(t *testing.T) {
	api := &freshnessAzureAPI{}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.False(t, statuses[0].IsScanAvailable)
	require.Empty(t, statuses[0].Status)
	require.True(t, statuses[0].LastScanDate.IsZero())
	require.Equal(t, freshnessAzureImage(), statuses[0].ImageID)
}

func TestAzureFreshness_IdenticalTimestampRowsAreStable(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z", "2026-10-14T00:00:00Z"}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.Equal(t, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), statuses[0].LastScanDate)
	require.Len(t, api.queries, 1)
}

func TestAzureFreshness_ProviderErrorIsPreserved(t *testing.T) {
	failure := errors.New("resource graph unavailable")
	api := &freshnessAzureAPI{failure: failure}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.ErrorIs(t, err, failure)
	require.ErrorContains(t, err, "team/app")
	require.False(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[0].LastScanDate.IsZero())
}

func TestAzureFreshness_CanceledContextIsNotTurnedIntoCleanStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(ctx, []ContainerImageIdentifier{freshnessAzureImage()})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, statuses[0].IsScanAvailable)
	require.Empty(t, statuses[0].Status)
}

func TestAzureFreshness_DeadlineErrorIsPreserved(t *testing.T) {
	api := &freshnessAzureAPI{failure: context.DeadlineExceeded}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, freshnessAzureImage(), statuses[0].ImageID)
	require.False(t, statuses[0].IsScanAvailable)
}

func TestAzureFreshness_NoDigestAvoidsQuery(t *testing.T) {
	api := &freshnessAzureAPI{failure: errors.New("must not query")}
	image := freshnessAzureImage()
	image.Hash = ""
	image.Tag = "latest"
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Empty(t, api.queries)
	require.False(t, statuses[0].IsScanAvailable)
	require.Equal(t, image, statuses[0].ImageID)
}

func TestAzureFreshness_ForeignRegistryStillDoesNotQuery(t *testing.T) {
	api := &freshnessAzureAPI{}
	image := freshnessAzureImage()
	image.Registry = "foreign.azurecr.io"
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "does not match")
	require.Empty(t, api.queries)
	require.False(t, statuses[0].IsScanAvailable)
}

func TestAzureFreshness_InvalidIdentifiersDoNotReachOrderingQuery(t *testing.T) {
	for _, field := range []string{"repository", "digest"} {
		api := &freshnessAzureAPI{}
		image := freshnessAzureImage()
		if field == "repository" {
			image.Repository = `team/app" | take 1`
		} else {
			image.Hash = `sha256:123" | take 1`
		}
		_, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
		require.ErrorContains(t, err, "invalid characters")
		require.Empty(t, api.queries)
	}
}

func TestAzureFreshness_RegistryCaseHandlingIsUnchanged(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
	image := freshnessAzureImage()
	image.Registry = "REGISTRY.AzureCR.IO"
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.True(t, statuses[0].IsScanAvailable)
	require.Equal(t, image, statuses[0].ImageID)
	require.Contains(t, *api.queries[0].Query, `registryName =~ "registry"`)
}

func TestAzureFreshness_MultipleImagesKeepTheirIdentityAndQueryDigest(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
	first := freshnessAzureImage()
	second := first
	second.Repository = "team/other"
	second.Hash = "sha256:456"
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{first, second})
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	require.Equal(t, first, statuses[0].ImageID)
	require.Equal(t, second, statuses[1].ImageID)
	require.Len(t, api.queries, 2)
	require.Contains(t, *api.queries[0].Query, first.Hash)
	require.Contains(t, *api.queries[1].Query, second.Hash)
	require.Equal(t, statuses[0].LastScanDate, statuses[1].LastScanDate)
}

func TestAzureFreshness_BatchContinuesAfterRejectedImage(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
	foreign := freshnessAzureImage()
	foreign.Registry = "foreign.azurecr.io"
	local := freshnessAzureImage()
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{foreign, local})
	require.Error(t, err)
	require.Len(t, statuses, 2)
	require.False(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[1].IsScanAvailable)
	require.Len(t, api.queries, 1)
}

func TestAzureFreshness_EmptyBatchMakesNoQuery(t *testing.T) {
	api := &freshnessAzureAPI{failure: errors.New("must not query")}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, statuses)
	require.Empty(t, api.queries)
}

func TestAzureFreshness_UninitializedClientStillRequiresLogin(t *testing.T) {
	statuses, err := NewAzureAdaptor().GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.ErrorContains(t, err, "not initialized")
	require.Nil(t, statuses)
}

func TestAzureFreshness_JSONPreservesNewestTimestamp(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2022-01-01T00:00:00Z", "2026-10-14T00:00:00.123456789Z"}}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	raw, err := json.Marshal(statuses)
	require.NoError(t, err)
	var decoded []ContainerImageScanStatus
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, statuses, decoded)
	require.Contains(t, string(raw), "2026-10-14T00:00:00.123456789Z")
	require.NotContains(t, string(raw), "2022-01-01")
}

func TestAzureFreshness_MissingTimestampFieldDoesNotInventDate(t *testing.T) {
	response := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		TotalRecords: to.Ptr[int64](1), Data: []interface{}{map[string]interface{}{}},
	}}
	api := &freshnessAzureAPI{response: &response}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.True(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[0].LastScanDate.IsZero())
}

func TestAzureFreshness_NonStringTimestampDoesNotInventDate(t *testing.T) {
	for _, timestamp := range []any{nil, float64(1728864000), true, map[string]any{"date": "2026-10-14"}} {
		response := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			TotalRecords: to.Ptr[int64](1), Data: []interface{}{map[string]interface{}{"timeGenerated": timestamp}},
		}}
		api := &freshnessAzureAPI{response: &response}
		statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
		require.NoError(t, err)
		require.True(t, statuses[0].LastScanDate.IsZero())
	}
}

func TestAzureFreshness_NilTotalsDoNotAssertAvailability(t *testing.T) {
	response := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		Data: []interface{}{map[string]interface{}{"timeGenerated": "2026-10-14T00:00:00Z"}},
	}}
	api := &freshnessAzureAPI{response: &response}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[0].LastScanDate.IsZero())
}

func TestAzureFreshness_ZeroTotalsDoNotTrustStrayResponseRows(t *testing.T) {
	response := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		TotalRecords: to.Ptr[int64](0), Data: []interface{}{map[string]interface{}{"timeGenerated": "2026-10-14T00:00:00Z"}},
	}}
	api := &freshnessAzureAPI{response: &response}
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	require.Empty(t, statuses[0].Status)
}

func TestAzureFreshness_LaterRequestObservesNewAssessment(t *testing.T) {
	api := &freshnessAzureAPI{dates: []string{"2025-01-01T00:00:00Z"}}
	a := freshnessAzureAdaptor(api)
	before, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	api.dates = append(api.dates, "2026-10-14T00:00:00Z")
	after, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.True(t, after[0].LastScanDate.After(before[0].LastScanDate))
	require.Equal(t, before[0].ImageID, after[0].ImageID)
}

func TestAzureFreshness_RequestDoesNotMutateProviderRows(t *testing.T) {
	dates := []string{"2022-01-01T00:00:00Z", "2026-10-14T00:00:00Z"}
	api := &freshnessAzureAPI{dates: dates}
	_, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Equal(t, dates, api.dates)
	require.Equal(t, "2022-01-01T00:00:00Z", api.dates[0])
}

func TestAzureFreshness_EmptyVulnerabilityReportUsesOrderedStatusQuery(t *testing.T) {
	var queries []string
	a := freshnessAzureAdaptor(&mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		query := *req.Query
		queries = append(queries, query)
		if strings.Contains(query, "assessments/subassessments") {
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: []interface{}{}}}, nil
		}
		require.Contains(t, query, "todatetime(properties.timeGenerated)")
		require.Contains(t, query, "order by timeGenerated desc nulls last")
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			TotalRecords: to.Ptr[int64](1), Data: []interface{}{map[string]interface{}{"timeGenerated": "2026-10-14T00:00:00Z"}},
		}}, nil
	}})
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Len(t, queries, 2)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, freshnessAzureImage(), reports[0].ImageID)
}

func TestAzureFreshness_AvailableCVEsDoNotAddStatusQuery(t *testing.T) {
	var queries []string
	a := freshnessAzureAdaptor(&mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		queries = append(queries, *req.Query)
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data: []interface{}{map[string]interface{}{"id": "CVE-local", "severity": "High", "description": "existing finding"}},
		}}, nil
	}})
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Len(t, queries, 1)
	require.Contains(t, queries[0], "assessments/subassessments")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-local", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestAzureFreshness_StatusFallbackErrorIsNotReportedAsCleanScan(t *testing.T) {
	failure := errors.New("status unavailable")
	calls := 0
	a := freshnessAzureAdaptor(&mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		if strings.Contains(*req.Query, "assessments/subassessments") {
			return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: []interface{}{}}}, nil
		}
		return armresourcegraph.ClientResourcesResponse{}, failure
	}})
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.ErrorIs(t, err, failure)
	require.Empty(t, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, 2, calls)
}

func TestAzureFreshness_SovereignRegistryQueriesKeepRegistryName(t *testing.T) {
	for _, suffix := range []string{"azurecr.io", "azurecr.cn", "azurecr.us"} {
		t.Run(suffix, func(t *testing.T) {
			api := &freshnessAzureAPI{dates: []string{"2026-10-14T00:00:00Z"}}
			a := &AzureAdaptor{registryHost: "registry." + suffix, client: api}
			image := freshnessAzureImage()
			image.Registry = a.registryHost
			statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Equal(t, image, statuses[0].ImageID)
			require.Contains(t, *api.queries[0].Query, `registryName =~ "registry"`)
			require.Contains(t, *api.queries[0].Query, "order by timeGenerated desc nulls last")
		})
	}
}

func TestAzureFreshness_EmptyStatusFallbackRemainsUnknown(t *testing.T) {
	calls := 0
	a := freshnessAzureAdaptor(&mockAzureClient{resourcesOut: func(_ armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			TotalRecords: to.Ptr[int64](0), Data: []interface{}{},
		}}, nil
	}})
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Empty(t, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, 2, calls)
}

func TestAzureFreshness_LargeAssessmentSetStillUsesOneBoundedQuery(t *testing.T) {
	api := &freshnessAzureAPI{dates: make([]string, 1001)}
	for i := range api.dates {
		api.dates[i] = "2022-01-01T00:00:00Z"
	}
	api.dates[1000] = "2026-10-14T00:00:00Z"
	statuses, err := freshnessAzureAdaptor(api).GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{freshnessAzureImage()})
	require.NoError(t, err)
	require.Equal(t, 2026, statuses[0].LastScanDate.Year())
	require.Len(t, api.queries, 1)
	require.Contains(t, *api.queries[0].Query, "limit 1")
	require.Nil(t, api.queries[0].Options.SkipToken)
}
