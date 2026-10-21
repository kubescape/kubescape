package imagescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHarborMalformedReportsAreNotCleanScans(t *testing.T) {
	for _, body := range []string{
		`null`, `{}`, `{"report":null}`, `{"report":{}}`,
		`{"report":{"severity":"Critical"}}`,
		`{"report":{"vulnerabilities":null}}`,
		`{"report":{"vulnerabilities":"not-an-array"}}`,
	} {
		t.Run(body, func(t *testing.T) {
			image := ContainerImageIdentifier{Repository: "project/app", Hash: "sha256:abc"}
			path := "/api/v2.0/projects/project/repositories/app/artifacts/sha256:abc/additions/vulnerabilities"
			adaptor := NewHarborAdaptor()
			adaptor.client = &mockHarborAPI{responses: map[string][]byte{path: []byte(body)}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.Len(t, reports, 1)
			require.Equal(t, image, reports[0].ImageID)
			require.NotEqual(t, ScanStatusScanned, reports[0].Status)
			require.Empty(t, reports[0].Vulnerabilities)
		})
	}
}

func TestHarborEmptyVulnerabilityArrayIsCleanScan(t *testing.T) {
	adaptor := NewHarborAdaptor()
	adaptor.client = &mockHarborAPI{responses: map[string][]byte{
		"/api/v2.0/projects/project/repositories/app/artifacts/latest/additions/vulnerabilities": []byte(`{"application/vnd.security.vulnerability.report; version=1.1":{"vulnerabilities":[]}}`),
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{{Repository: "project/app", Tag: "latest"}})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestHarborInvalidScannerReportPreservesValidFindings(t *testing.T) {
	adaptor := NewHarborAdaptor()
	adaptor.client = &mockHarborAPI{responses: map[string][]byte{
		"/api/v2.0/projects/project/repositories/app/artifacts/latest/additions/vulnerabilities": []byte(`{
			"valid":{"vulnerabilities":[{"id":"CVE-2026-1234","severity":"Critical"}]},
			"invalid":{}
		}`),
	}}
	for i := 0; i < 20; i++ {
		reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{{Repository: "project/app", Tag: "latest"}})
		require.Error(t, err)
		require.NotEqual(t, ScanStatusScanned, reports[0].Status)
		require.Len(t, reports[0].Vulnerabilities, 1)
		require.Equal(t, "CVE-2026-1234", reports[0].Vulnerabilities[0].ID)
	}
}

func TestHarborMalformedReportThroughHTTPAndMixedBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v2.0/systeminfo":
			fmt.Fprint(w, `{}`)
		case strings.Contains(r.URL.Path, "/bad/"):
			fmt.Fprint(w, `{"report":{"error":"scanner unavailable"}}`)
		default:
			fmt.Fprint(w, `{"report":{"vulnerabilities":[{"id":"CVE-2026-4321","severity":"High"}]}}`)
		}
	}))
	defer server.Close()
	adaptor := NewHarborAdaptor()
	require.NoError(t, adaptor.Login(context.Background(), server.URL, RegistryCredentials{}))
	images := []ContainerImageIdentifier{
		{Repository: "project/good", Tag: "latest"},
		{Repository: "project/bad", Tag: "latest"},
		{Repository: "project/after", Tag: "latest"},
	}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.Error(t, err)
	require.Len(t, reports, 3)
	for i := range images {
		require.Equal(t, images[i], reports[i].ImageID)
	}
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Empty(t, reports[1].Status)
	require.Equal(t, ScanStatusScanned, reports[2].Status)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Len(t, reports[2].Vulnerabilities, 1)
}
