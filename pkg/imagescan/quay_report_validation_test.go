package imagescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuayMissingSecurityReportIsNotClean(t *testing.T) {
	for _, payload := range []string{
		`{"status":"scanned"}`,
		`{"status":"scanned","data":null}`,
		`{"status":"scanned","data":{}}`,
		`{"status":"scanned","data":{"Layer":null}}`,
	} {
		for _, child := range []bool{false, true} {
			name := "direct/" + payload
			if child {
				name = "manifest child/" + payload
			}
			t.Run(name, func(t *testing.T) {
				api := newMockQuayAPI()
				image := ContainerImageIdentifier{Registry: "quay.io", Repository: "team/app", Hash: "sha256:parent"}
				parentPath := quayManifestSecurityPath("team", "app", image.Hash, true)
				if child {
					api.responses[parentPath] = []byte(`{"status":"unsupported"}`)
					api.mockManifest("team", "app", image.Hash, true, `{"manifests":[{"digest":"sha256:child","platform":{"os":"linux","architecture":"amd64"}}]}`)
					api.responses[quayManifestSecurityPath("team", "app", "sha256:child", true)] = []byte(payload)
				} else {
					api.responses[parentPath] = []byte(payload)
				}
				reports, err := (&QuayAdaptor{client: api, registryHost: "quay.io"}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
				require.ErrorContains(t, err, "missing security report data")
				require.Len(t, reports, 1)
				require.Equal(t, image, reports[0].ImageID)
				require.NotEqual(t, ScanStatusScanned, reports[0].Status)
				require.Empty(t, reports[0].Vulnerabilities)
				require.Equal(t, 1, api.calls[parentPath])
			})
		}
	}
}

func TestQuayPresentEmptySecurityReportStillSucceeds(t *testing.T) {
	for _, layer := range []string{`{}`, `{"Features":[]}`, `{"Features":[{"Name":"openssl","Vulnerabilities":[]}]}`} {
		t.Run(layer, func(t *testing.T) {
			api := newMockQuayAPI()
			image := ContainerImageIdentifier{Registry: "quay.io", Repository: "team/app", Hash: "sha256:clean"}
			api.responses[quayManifestSecurityPath("team", "app", image.Hash, true)] = []byte(`{"status":"scanned","data":{"Layer":` + layer + `}}`)
			reports, err := (&QuayAdaptor{client: api, registryHost: "quay.io"}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Equal(t, ScanStatusScanned, reports[0].Status)
			require.Empty(t, reports[0].Vulnerabilities)
		})
	}
}

func TestQuayMissingReportDoesNotDiscardOtherImages(t *testing.T) {
	api := newMockQuayAPI()
	first := ContainerImageIdentifier{Registry: "quay.io", Repository: "team/app", Hash: "sha256:missing"}
	second := first
	second.Hash = "sha256:available"
	api.responses[quayManifestSecurityPath("team", "app", first.Hash, true)] = []byte(`{"status":"scanned","data":null}`)
	api.responses[quayManifestSecurityPath("team", "app", second.Hash, true)] = []byte(`{"status":"scanned","data":{"Layer":{"Features":[{"Name":"openssl","Vulnerabilities":[{"Name":"CVE-retained","Severity":"High"}]}]}}}`)
	reports, err := (&QuayAdaptor{client: api, registryHost: "quay.io"}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{first, second})
	require.Error(t, err)
	require.Len(t, reports, 2)
	require.Equal(t, first, reports[0].ImageID)
	require.NotEqual(t, ScanStatusScanned, reports[0].Status)
	require.Equal(t, second, reports[1].ImageID)
	require.Equal(t, ScanStatusScanned, reports[1].Status)
	require.Len(t, reports[1].Vulnerabilities, 1)
	require.Equal(t, "CVE-retained", reports[1].Vulnerabilities[0].ID)
}

func TestQuayMissingReportThroughHTTP(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer report-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		requests++
		w.Header().Set("Content-Type", "application/json")
		// Status-only lookups intentionally do not request the full report.
		if r.URL.Query().Get("vulnerabilities") == "false" {
			fmt.Fprint(w, `{"status":"scanned"}`)
			return
		}
		fmt.Fprint(w, `{"status":"scanned","data":null}`)
	}))
	defer server.Close()
	api := &quayAPIWrapper{baseURL: server.URL, token: "report-token", httpClient: server.Client()}
	adaptor := &QuayAdaptor{client: api, registryHost: "quay.io"}
	images := []ContainerImageIdentifier{{Registry: "quay.io", Repository: "team/app", Hash: "sha256:report"}}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.NoError(t, err)
	require.True(t, statuses[0].IsScanAvailable)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "missing security report data")
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Status)
	require.Equal(t, 2, requests)
}

func TestQuayEmptyChildReportStillSucceeds(t *testing.T) {
	api := newMockQuayAPI()
	image := ContainerImageIdentifier{Registry: "quay.io", Repository: "team/app", Hash: "sha256:parent"}
	api.responses[quayManifestSecurityPath("team", "app", image.Hash, true)] = []byte(`{"status":"unsupported"}`)
	api.mockManifest("team", "app", image.Hash, true, `{"manifests":[{"digest":"sha256:child","platform":{"os":"linux","architecture":"amd64"}}]}`)
	api.responses[quayManifestSecurityPath("team", "app", "sha256:child", true)] = []byte(`{"status":"scanned","data":{"Layer":{"Features":[]}}}`)
	reports, err := (&QuayAdaptor{client: api, registryHost: "quay.io"}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestQuayNonCompletedReportsDoNotRequireLayer(t *testing.T) {
	for _, status := range []ScanStatus{ScanStatusQueued, ScanStatusFailed, ScanStatusUnsupported} {
		t.Run(string(status), func(t *testing.T) {
			api := newMockQuayAPI()
			image := ContainerImageIdentifier{Registry: "quay.io", Repository: "team/app", Hash: "sha256:single"}
			api.responses[quayManifestSecurityPath("team", "app", image.Hash, true)] = []byte(`{"status":"` + string(status) + `","data":null}`)
			// Confirm the unsupported digest is an ordinary image, not a list.
			api.mockManifest("team", "app", image.Hash, false, `{}`)
			reports, err := (&QuayAdaptor{client: api, registryHost: "quay.io"}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			if status == ScanStatusUnsupported {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, status, reports[0].Status)
		})
	}
}
