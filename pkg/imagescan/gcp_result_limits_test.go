package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

func limitedGCPFindings(count int) []*grafeaspb.Occurrence {
	findings := make([]*grafeaspb.Occurrence, count)
	for i := range findings {
		findings[i] = partialGCPVulnerability(fmt.Sprintf("CVE-%04d", i))
	}
	return findings
}

func TestGCPFindingLimitReportsIncompleteResults(t *testing.T) {
	for _, count := range []int{0, 999, 1000, 1001, 1005} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			api := &partialGCPAPI{
				discovery: []*grafeaspb.Occurrence{discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})},
				findings:  limitedGCPFindings(count),
			}
			adaptor := &GCPAdaptor{client: api, projectID: "project"}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
			if count > 1000 {
				require.ErrorContains(t, err, "1000")
				require.ErrorContains(t, err, "incomplete")
			} else {
				require.NoError(t, err, "a full final page is not evidence of omitted findings")
			}
			require.Len(t, reports, 1)
			require.Len(t, reports[0].Vulnerabilities, min(count, 1000))
			require.Equal(t, ScanStatusScanned, reports[0].Status, "discovery completion and finding completeness are separate")
			if count > 0 {
				require.Equal(t, "CVE-0000", reports[0].Vulnerabilities[0].ID)
				require.Equal(t, fmt.Sprintf("CVE-%04d", min(count, 1000)-1), reports[0].Vulnerabilities[min(count, 1000)-1].ID)
			}
		})
	}
}

func TestGCPFindingLimitPreservesDiscoveryErrors(t *testing.T) {
	failed := errors.New("discovery unavailable")
	api := &partialGCPAPI{discoveryErr: failed, findings: limitedGCPFindings(1001)}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Empty(t, reports[0].Status)
	encoded, encodeErr := json.Marshal(reports[0])
	require.NoError(t, encodeErr)
	require.Contains(t, string(encoded), "CVE-0999", "partial findings must remain available for report output")
}

type countedGCPIterator struct {
	next func() (*grafeaspb.Occurrence, error)
}

func (it countedGCPIterator) Next() (*grafeaspb.Occurrence, error) { return it.next() }

func TestGCPFindingLimitBoundsIteratorConsumption(t *testing.T) {
	reads := 0
	api := &partialGCPAPI{call: func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
			return &mockGrafeasIterator{}
		}
		return countedGCPIterator{next: func() (*grafeaspb.Occurrence, error) {
			reads++
			if reads > 1001 {
				return nil, errors.New("read beyond the bounded overflow probe")
			}
			return partialGCPVulnerability(fmt.Sprintf("CVE-%d", reads)), nil
		}}
	}}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorContains(t, err, "incomplete")
	require.Equal(t, 1001, reads, "read one extra occurrence to distinguish exact completion from overflow")
	require.Len(t, reports[0].Vulnerabilities, 1000)
}

func TestGCPFindingLimitDoesNotHideBoundaryIteratorFailure(t *testing.T) {
	failed := errors.New("next page unavailable")
	api := &partialGCPAPI{findings: limitedGCPFindings(1000), findingsErr: failed}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.NotContains(t, err.Error(), "limit", "an unreadable page is not proven overflow")
}

func TestGCPLimitedImageDoesNotDiscardOtherImages(t *testing.T) {
	api := &partialGCPAPI{call: func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
			return &mockGrafeasIterator{}
		}
		count := 1
		if strings.Contains(req.Filter, "sha256:large") {
			count = 1001
		}
		return &mockGrafeasIterator{occurrences: limitedGCPFindings(count)}
	}}
	images := []ContainerImageIdentifier{partialGCPImage(), partialGCPImage()}
	images[0].Hash = "sha256:large"
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports, 2)
	require.Equal(t, images[0], reports[0].ImageID)
	require.Equal(t, images[1], reports[1].ImageID)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Len(t, reports[1].Vulnerabilities, 1)
}

func TestGCPDiscoveryLimitReportsIncompleteStatus(t *testing.T) {
	for _, count := range []int{0, 999, 1000, 1001} {
		for _, completed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/completed=%v", count, completed), func(t *testing.T) {
				occurrences := make([]*grafeaspb.Occurrence, count)
				for i := range occurrences {
					occurrences[i] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{})
				}
				if completed && count > 0 {
					occurrences[0] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})
				}
				api := &partialGCPAPI{discovery: occurrences}
				adaptor := &GCPAdaptor{client: api, projectID: "project"}
				statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
				if count > 1000 {
					require.ErrorContains(t, err, "incomplete")
				} else {
					require.NoError(t, err)
				}
				require.Len(t, statuses, 1)
				require.Equal(t, completed && count > 0, statuses[0].IsScanAvailable)
			})
		}
	}
}

func TestGCPDiscoveryOverflowStillFetchesVulnerabilities(t *testing.T) {
	api := &partialGCPAPI{findings: limitedGCPFindings(1)}
	for i := 0; i < 1001; i++ {
		api.discovery = append(api.discovery, discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}))
	}
	// A successful occurrence outside the bounded prefix cannot justify a
	// completed status. The returned error must distinguish this from pending.
	api.discovery[1000] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Empty(t, reports[0].Status)
	require.Len(t, api.requests, 2, "a discovery limit must not suppress independently available CVEs")
}

func TestGCPDiscoveryBoundaryFailureRemainsDiscoverable(t *testing.T) {
	failed := errors.New("discovery continuation failed")
	api := &partialGCPAPI{discoveryErr: failed}
	for i := 0; i < 1000; i++ {
		api.discovery = append(api.discovery, discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}))
	}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, statuses, 1)
	require.False(t, statuses[0].IsScanAvailable)
}

func TestGCPDiscoveryLimitBoundsIteratorConsumption(t *testing.T) {
	reads := 0
	api := &partialGCPAPI{call: func(context.Context, *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		return countedGCPIterator{next: func() (*grafeaspb.Occurrence, error) {
			reads++
			if reads > 1001 {
				return nil, iterator.Done
			}
			return discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}), nil
		}}
	}}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	_, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorContains(t, err, "incomplete")
	require.Equal(t, 1001, reads)
}

func TestGCPDiscoveryLimitKeepsNewestRetainedCompletion(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	last := first.Add(time.Hour)
	api := &partialGCPAPI{}
	for i := 0; i < 1001; i++ {
		api.discovery = append(api.discovery, discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}))
	}
	api.discovery[0] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, first)
	api.discovery[999] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, last)
	api.discovery[1000] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, last.Add(time.Hour))
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorContains(t, err, "incomplete")
	require.True(t, statuses[0].IsScanAvailable)
	require.Equal(t, last, statuses[0].LastScanDate, "overflow must not replace the latest completion in the retained prefix")
}

func TestGCPDiscoveryLimitKeepsBatchAlignment(t *testing.T) {
	api := &partialGCPAPI{call: func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		count := 1
		if strings.Contains(req.Filter, "sha256:large") {
			count = 1001
		}
		occurrences := make([]*grafeaspb.Occurrence, count)
		for i := range occurrences {
			occurrences[i] = discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})
		}
		return &mockGrafeasIterator{occurrences: occurrences}
	}}
	images := []ContainerImageIdentifier{partialGCPImage(), partialGCPImage()}
	images[0].Hash = "sha256:large"
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, statuses, 2)
	require.Equal(t, images[0], statuses[0].ImageID)
	require.Equal(t, images[1], statuses[1].ImageID)
	require.True(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[1].IsScanAvailable)
}

func TestGCPCancellationAtFindingLimitIsNotReportedAsCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	api := &partialGCPAPI{call: func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
			return &mockGrafeasIterator{}
		}
		return countedGCPIterator{next: func() (*grafeaspb.Occurrence, error) {
			reads++
			if reads == 1001 {
				cancel()
				return nil, ctx.Err()
			}
			return partialGCPVulnerability(fmt.Sprintf("CVE-%d", reads)), nil
		}}
	}}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Equal(t, 1001, reads)
}

func TestGCPBothResultLimitsRemainVisible(t *testing.T) {
	// Discovery and findings are independent bounded queries. Their errors
	// must coexist without dropping the report's identity or retained CVEs.
	api := &partialGCPAPI{findings: limitedGCPFindings(1001)}
	for i := 0; i < 1001; i++ {
		api.discovery = append(api.discovery, discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}))
	}
	adaptor := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.Error(t, err)
	require.ErrorContains(t, err, "1000-occurrence limit")
	require.ErrorContains(t, err, "1000-finding limit")
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Empty(t, reports[0].Status)
	require.Len(t, api.requests, 2)
	require.Equal(t, partialGCPImage(), reports[0].ImageID)
	require.Equal(t, "CVE-0000", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-0999", reports[0].Vulnerabilities[999].ID)
	require.ErrorContains(t, err, "repository project/repo/app")
}
