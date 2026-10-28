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
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type partialGCPAPI struct {
	discoveryErr error
	discovery    []*grafeaspb.Occurrence
	findingsErr  error
	findings     []*grafeaspb.Occurrence
	requests     []*grafeaspb.ListOccurrencesRequest
	call         func(context.Context, *grafeaspb.ListOccurrencesRequest) GrafeasIterator
}

func (api *partialGCPAPI) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, _ ...interface{}) GrafeasIterator {
	api.requests = append(api.requests, req)
	if api.call != nil {
		return api.call(ctx, req)
	}
	if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
		return &mockGrafeasIterator{occurrences: api.discovery, err: api.discoveryErr, errorAfter: len(api.discovery)}
	}
	return &mockGrafeasIterator{occurrences: api.findings, err: api.findingsErr, errorAfter: len(api.findings)}
}

func partialGCPImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{Registry: "us-docker.pkg.dev", Repository: "project/repo/app", Hash: "sha256:123"}
}

func partialGCPVulnerability(id string) *grafeaspb.Occurrence {
	return &grafeaspb.Occurrence{Details: &grafeaspb.Occurrence_Vulnerability{
		Vulnerability: &grafeaspb.VulnerabilityOccurrence{ShortDescription: id, EffectiveSeverity: grafeaspb.Severity_CRITICAL},
	}}
}

func TestGCPPartialFindings_BothProviderErrorsRemainDiscoverable(t *testing.T) {
	discoveryError := errors.New("discovery permission denied")
	findingsError := errors.New("findings page unavailable")
	api := &partialGCPAPI{
		discoveryErr: discoveryError,
		findingsErr:  findingsError,
		findings:     []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-first")},
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, discoveryError)
	require.ErrorIs(t, err, findingsError)
	require.ErrorContains(t, err, "failed to query scan status")
	require.ErrorContains(t, err, "failed to query vulnerabilities")
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
	require.Empty(t, reports[0].Status)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_CompletedDiscoverySurvivesLaterDiscoveryFailure(t *testing.T) {
	failed := errors.New("later discovery page failed")
	api := &partialGCPAPI{
		discoveryErr: failed,
		discovery: []*grafeaspb.Occurrence{
			discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)),
		},
		findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")},
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Equal(t, "CVE-available", reports[0].Vulnerabilities[0].ID)
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.True(t, statuses[0].IsScanAvailable)
	require.Equal(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), statuses[0].LastScanDate)
}

func TestGCPPartialFindings_UnfinishedDiscoveryDoesNotBecomeCleanScan(t *testing.T) {
	for _, state := range []grafeaspb.DiscoveryOccurrence_AnalysisStatus{
		grafeaspb.DiscoveryOccurrence_PENDING,
		grafeaspb.DiscoveryOccurrence_SCANNING,
		grafeaspb.DiscoveryOccurrence_FINISHED_FAILED,
		grafeaspb.DiscoveryOccurrence_ANALYSIS_STATUS_UNSPECIFIED,
	} {
		t.Run(state.String(), func(t *testing.T) {
			failed := errors.New("discovery continuation failed")
			api := &partialGCPAPI{
				discoveryErr: failed,
				discovery:    []*grafeaspb.Occurrence{discoveryOccurrence(state, time.Time{})},
				findings:     []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")},
			}
			a := &GCPAdaptor{client: api, projectID: "project"}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
			require.ErrorIs(t, err, failed)
			require.Empty(t, reports[0].Status)
			require.Len(t, reports[0].Vulnerabilities, 1)
			require.Equal(t, "Critical", reports[0].Vulnerabilities[0].Severity)
		})
	}
}

func TestGCPPartialFindings_EmptyFindingsKeepDiscoveryError(t *testing.T) {
	failed := errors.New("discovery inaccessible")
	api := &partialGCPAPI{discoveryErr: failed}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
	require.Len(t, api.requests, 2)
	require.Contains(t, api.requests[1].Filter, `kind="VULNERABILITY"`)
}

func TestGCPPartialFindings_QueryScopeAndDigestAreUnchanged(t *testing.T) {
	failed := errors.New("discovery failed")
	api := &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "owner-project"}
	image := partialGCPImage()
	image.Tag = "ignored-tag"
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, failed)
	require.Len(t, api.requests, 2)
	for _, request := range api.requests {
		require.Equal(t, "projects/owner-project", request.Parent)
		require.Contains(t, request.Filter, "https://us-docker.pkg.dev/project/repo/app@sha256:123")
		require.NotContains(t, request.Filter, "ignored-tag")
	}
	require.Contains(t, api.requests[0].Filter, `kind="DISCOVERY"`)
	require.Contains(t, api.requests[1].Filter, `kind="VULNERABILITY"`)
	require.Equal(t, int32(1000), api.requests[1].PageSize)
	require.Equal(t, image, reports[0].ImageID)
}

func TestGCPPartialFindings_FindingFieldsAndNoteFallbackArePreserved(t *testing.T) {
	failed := errors.New("discovery unavailable")
	first := partialGCPVulnerability("CVE-critical")
	first.GetVulnerability().LongDescription = "critical package finding"
	first.GetVulnerability().RelatedUrls = []*grafeaspb.RelatedUrl{{Url: "https://advisories.example/critical"}}
	second := partialGCPVulnerability("")
	second.NoteName = "projects/provider/notes/CVE-note"
	second.GetVulnerability().EffectiveSeverity = grafeaspb.Severity_HIGH
	api := &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{first, second}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 2)
	require.Equal(t, "CVE-critical", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "critical package finding", reports[0].Vulnerabilities[0].Description)
	require.Equal(t, []string{"https://advisories.example/critical"}, reports[0].Vulnerabilities[0].Links)
	require.Equal(t, "CVE-note", reports[0].Vulnerabilities[1].ID)
	require.Equal(t, "High", reports[0].Vulnerabilities[1].Severity)
}

func TestGCPPartialFindings_IgnoresNonVulnerabilityOccurrences(t *testing.T) {
	failed := errors.New("discovery unavailable")
	api := &partialGCPAPI{
		discoveryErr: failed,
		findings: []*grafeaspb.Occurrence{
			nil, {}, discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{}),
			partialGCPVulnerability("CVE-real"),
		},
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-real", reports[0].Vulnerabilities[0].ID)
	require.Empty(t, reports[0].Status)
}

func TestGCPPartialFindings_MixedImageBatchesContinueAfterDiscoveryFailure(t *testing.T) {
	badImage := partialGCPImage()
	goodImage := badImage
	goodImage.Repository = "project/repo/healthy"
	failed := errors.New("first image discovery failed")
	api := &partialGCPAPI{}
	api.call = func(_ context.Context, request *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		if strings.Contains(request.Filter, `kind="DISCOVERY"`) {
			if strings.Contains(request.Filter, badImage.Repository+"@") {
				return &mockGrafeasIterator{err: failed}
			}
			return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})}}
		}
		id := "CVE-first"
		if strings.Contains(request.Filter, goodImage.Repository+"@") {
			id = "CVE-second"
		}
		return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{partialGCPVulnerability(id)}}
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{badImage, goodImage})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports, 2)
	require.Equal(t, badImage, reports[0].ImageID)
	require.Equal(t, goodImage, reports[1].ImageID)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-second", reports[1].Vulnerabilities[0].ID)
	require.Empty(t, reports[0].Status)
	require.Equal(t, ScanStatusScanned, reports[1].Status)
	require.Len(t, api.requests, 4)
}

func TestGCPPartialFindings_ContextCancellationStopsIndependentQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	failed := errors.New("discovery interrupted")
	api := &partialGCPAPI{}
	api.call = func(context.Context, *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		cancel()
		return &mockGrafeasIterator{err: failed}
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Len(t, api.requests, 1)
}

func TestGCPPartialFindings_ProviderDeadlineDoesNotCancelLiveContext(t *testing.T) {
	api := &partialGCPAPI{discoveryErr: context.DeadlineExceeded, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_NoDigestStillSkipsBothQueries(t *testing.T) {
	api := &partialGCPAPI{discoveryErr: errors.New("must not be queried")}
	a := &GCPAdaptor{client: api, projectID: "project"}
	image := partialGCPImage()
	image.Hash = ""
	image.Tag = "tag-only"
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
	require.Empty(t, api.requests)
}

func TestGCPPartialFindings_BoundedFindingsStillReturnDiscoveryError(t *testing.T) {
	failed := errors.New("discovery unavailable")
	api := &partialGCPAPI{discoveryErr: failed}
	for i := 0; i < 1002; i++ {
		api.findings = append(api.findings, partialGCPVulnerability(fmt.Sprintf("CVE-%04d", i)))
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.ErrorContains(t, err, "incomplete")
	require.Len(t, reports[0].Vulnerabilities, 1000)
	require.Equal(t, "CVE-0000", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-0999", reports[0].Vulnerabilities[999].ID)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_SerializedReportKeepsCVEsWithoutCleanStatus(t *testing.T) {
	failed := errors.New("discovery unavailable")
	api := &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	raw, err := json.Marshal(reports)
	require.NoError(t, err)
	require.Contains(t, string(raw), "CVE-available")
	require.NotContains(t, string(raw), `"status":"scanned"`)
	var decoded []ContainerImageVulnerabilityReport
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, reports[0].ImageID, decoded[0].ImageID)
	require.Equal(t, reports[0].Vulnerabilities[0].ID, decoded[0].Vulnerabilities[0].ID)
}

func TestGCPPartialFindings_InvalidDiscoveryTimestampDoesNotDiscardCVEs(t *testing.T) {
	failed := errors.New("discovery unavailable")
	discovery := discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})
	discovery.UpdateTime = &timestamppb.Timestamp{Seconds: 253402300800}
	api := &partialGCPAPI{discoveryErr: failed, discovery: []*grafeaspb.Occurrence{discovery}, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestGCPPartialFindings_SuccessfulEmptyScanStillReportsScanned(t *testing.T) {
	api := &partialGCPAPI{discovery: []*grafeaspb.Occurrence{discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.NoError(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_FindingsOnlyFailureStillReturnsPartialResult(t *testing.T) {
	failed := errors.New("findings interrupted")
	api := &partialGCPAPI{
		findingsErr: failed,
		discovery:   []*grafeaspb.Occurrence{discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})},
		findings:    []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-first")},
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_AllSeveritiesSurviveDiscoveryFailure(t *testing.T) {
	for _, tc := range []struct {
		input    grafeaspb.Severity
		expected string
	}{
		{grafeaspb.Severity_CRITICAL, "Critical"},
		{grafeaspb.Severity_HIGH, "High"},
		{grafeaspb.Severity_MEDIUM, "Medium"},
		{grafeaspb.Severity_LOW, "Low"},
		{grafeaspb.Severity_MINIMAL, "Negligible"},
		{grafeaspb.Severity_SEVERITY_UNSPECIFIED, "Unknown"},
	} {
		t.Run(tc.input.String(), func(t *testing.T) {
			failed := errors.New("discovery unavailable")
			occurrence := partialGCPVulnerability("CVE-severity")
			occurrence.GetVulnerability().EffectiveSeverity = tc.input
			api := &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{occurrence}}
			a := &GCPAdaptor{client: api, projectID: "project"}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
			require.ErrorIs(t, err, failed)
			require.Equal(t, tc.expected, reports[0].Vulnerabilities[0].Severity)
			require.Empty(t, reports[0].Status)
		})
	}
}

func TestGCPPartialFindings_AggregatesIndependentFailuresAcrossImages(t *testing.T) {
	firstDiscovery := errors.New("first discovery failed")
	firstFindings := errors.New("first findings failed")
	secondDiscovery := errors.New("second discovery failed")
	secondFindings := errors.New("second findings failed")
	first := partialGCPImage()
	second := first
	second.Repository = "project/repo/second"
	api := &partialGCPAPI{}
	api.call = func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		isSecond := strings.Contains(req.Filter, second.Repository+"@")
		if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
			if isSecond {
				return &mockGrafeasIterator{err: secondDiscovery}
			}
			return &mockGrafeasIterator{err: firstDiscovery}
		}
		failed := firstFindings
		id := "CVE-first"
		if isSecond {
			failed = secondFindings
			id = "CVE-second"
		}
		return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{partialGCPVulnerability(id)}, err: failed, errorAfter: 1}
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{first, second})
	for _, failed := range []error{firstDiscovery, firstFindings, secondDiscovery, secondFindings} {
		require.ErrorIs(t, err, failed)
	}
	require.Len(t, reports, 2)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-second", reports[1].Vulnerabilities[0].ID)
	require.Len(t, api.requests, 4)
}

func TestGCPPartialFindings_CancellationDuringFindingsKeepsEarlierCVEs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := errors.New("discovery unavailable")
	api := &partialGCPAPI{}
	api.call = func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
			return &mockGrafeasIterator{err: failed}
		}
		cancel()
		return &mockGrafeasIterator{
			occurrences: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-before-cancel")},
			err:         context.Canceled,
			errorAfter:  1,
		}
	}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, failed)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-before-cancel", reports[0].Vulnerabilities[0].ID)
	require.Len(t, api.requests, 2)
}

func TestGCPPartialFindings_SubsequentCallCanRecoverDiscovery(t *testing.T) {
	failed := errors.New("temporary discovery outage")
	api := &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	image := partialGCPImage()
	before, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, failed)
	require.Empty(t, before[0].Status)
	require.Len(t, before[0].Vulnerabilities, 1)
	api.discoveryErr = nil
	api.discovery = []*grafeaspb.Occurrence{discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{})}
	after, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Equal(t, ScanStatusScanned, after[0].Status)
	require.Equal(t, before[0].Vulnerabilities, after[0].Vulnerabilities)
	require.Equal(t, image, after[0].ImageID)
	require.Len(t, api.requests, 4)
}

func TestGCPPartialFindings_AlreadyCanceledContextDoesNotFetchCVEs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	api := &partialGCPAPI{discoveryErr: context.Canceled}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Len(t, api.requests, 1)
}

func TestGCPPartialFindings_NoClientStillRequiresLogin(t *testing.T) {
	a := NewGCPAdaptor()
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.ErrorContains(t, err, "not initialized")
	require.Nil(t, reports)
}

func TestGCPPartialFindings_EmptyBatchNeverQueriesProvider(t *testing.T) {
	api := &partialGCPAPI{discoveryErr: errors.New("must not be queried")}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, reports)
	require.Empty(t, api.requests)
}

func TestGCPPartialFindings_AllEmptyImagesKeepBatchShape(t *testing.T) {
	api := &partialGCPAPI{discoveryErr: errors.New("must not be queried")}
	a := &GCPAdaptor{client: api, projectID: "project"}
	images := []ContainerImageIdentifier{
		{Registry: "us-docker.pkg.dev", Repository: "project/repo/a", Tag: "one"},
		{Registry: "eu-docker.pkg.dev", Repository: "project/repo/b", Tag: "two"},
	}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, len(images))
	for i, report := range reports {
		require.Equal(t, images[i], report.ImageID)
		require.Empty(t, report.Vulnerabilities)
		require.Empty(t, report.Status)
	}
	require.Empty(t, api.requests)
}

func TestGCPPartialFindings_DiscoveryFailureDoesNotDiscardCVEs(t *testing.T) {
	failed := errors.New("discovery unavailable")
	a := &GCPAdaptor{client: &partialGCPAPI{discoveryErr: failed, findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}, projectID: "project"}
	image := ContainerImageIdentifier{Registry: "us-docker.pkg.dev", Repository: "project/repo/app", Hash: "sha256:123"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, failed)
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-available", reports[0].Vulnerabilities[0].ID)
}

func TestGCPPartialFindings_MissingDiscoveryIsNotReportedAsCompleted(t *testing.T) {
	api := &partialGCPAPI{findings: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-available")}}
	a := &GCPAdaptor{client: api, projectID: "project"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
	require.NoError(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Empty(t, reports[0].Status)
	require.Len(t, api.requests, 2)
}
