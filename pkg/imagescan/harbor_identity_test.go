package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type identityHarborAPI struct {
	paths []string
	call  func(string) ([]byte, error)
}

func (api *identityHarborAPI) DoRequest(_ context.Context, _ string, path string) ([]byte, error) {
	api.paths = append(api.paths, path)
	if api.call != nil {
		return api.call(path)
	}
	if strings.HasSuffix(path, "/additions/vulnerabilities") {
		return []byte(`{"scanner":{"vulnerabilities":[{"id":"CVE-local","severity":"Critical"}]}}`), nil
	}
	return []byte(`{"scan_overview":{"scanner":{"scan_status":"Success","end_time":"2026-01-02T03:04:05Z"}}}`), nil
}

func TestHarborIdentity_ValidAuthorityFormsKeepLocalResults(t *testing.T) {
	for _, tc := range []struct{ host, registry string }{
		{"harbor.example", "harbor.example"},
		{"harbor.example", "HARBOR.example"},
		{"harbor.example:8443", "harbor.example:8443"},
		{"harbor.example", "https://harbor.example"},
		{"https://harbor.example/", "harbor.example"},
		{"http://harbor.example:8080", "harbor.example:8080"},
		{"[::1]:8443", "[::1]:8443"},
		{"harbor.example", ""},
	} {
		t.Run(tc.host+"/"+tc.registry, func(t *testing.T) {
			api := &identityHarborAPI{}
			a := &HarborAdaptor{host: tc.host, client: api}
			image := ContainerImageIdentifier{Registry: tc.registry, Repository: "team/app", Tag: "release"}
			statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Len(t, statuses, 1)
			require.Equal(t, image, statuses[0].ImageID)
			require.True(t, statuses[0].IsScanAvailable)
			require.Equal(t, ScanStatusScanned, statuses[0].Status)
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Equal(t, image, reports[0].ImageID)
			require.Equal(t, "CVE-local", reports[0].Vulnerabilities[0].ID)
			require.Len(t, api.paths, 2)
		})
	}
}

func TestHarborIdentity_ForeignAuthorityNeverMakesAPIRequests(t *testing.T) {
	for _, registry := range []string{
		"other.example", "child.harbor.example", "harbor.example.evil",
		"harbor.example:8443", "https://other.example", "127.0.0.1:443",
	} {
		for _, reference := range []string{"tag", "digest"} {
			t.Run(registry+"/"+reference, func(t *testing.T) {
				api := &identityHarborAPI{}
				a := &HarborAdaptor{host: "harbor.example", client: api}
				image := ContainerImageIdentifier{Registry: registry, Repository: "team/app", Tag: "release"}
				if reference == "digest" {
					image.Hash = "sha256:123"
				}
				statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
				require.ErrorContains(t, err, "does not match")
				require.Equal(t, image, statuses[0].ImageID)
				require.False(t, statuses[0].IsScanAvailable)
				require.Empty(t, statuses[0].Status)
				reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
				require.ErrorContains(t, err, "does not match")
				require.Equal(t, image, reports[0].ImageID)
				require.Empty(t, reports[0].Vulnerabilities)
				require.Empty(t, reports[0].Status)
				require.Empty(t, api.paths)
			})
		}
	}
}

func TestHarborIdentity_InvalidAuthorityDoesNotReachAPI(t *testing.T) {
	for _, registry := range []string{
		"https://robot:password@harbor.example", "https://harbor.example/other",
		"harbor.example?token=test", "harbor.example#fragment", "ftp://harbor.example",
		"https://", "https://harbor.example:bad", "https://harbor.example/%zz",
		"/harbor.example", "https://harbor.example//",
	} {
		t.Run(registry, func(t *testing.T) {
			api := &identityHarborAPI{}
			a := &HarborAdaptor{host: "harbor.example", client: api}
			image := ContainerImageIdentifier{Registry: registry, Repository: "team/app", Tag: "release"}
			statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.False(t, statuses[0].IsScanAvailable)
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.Empty(t, reports[0].Vulnerabilities)
			require.Empty(t, api.paths)
		})
	}
}

func TestHarborIdentity_MixedBatchKeepsResultsInInputOrder(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	images := []ContainerImageIdentifier{
		{Registry: "other.example", Repository: "team/app", Tag: "release"},
		{Registry: "harbor.example", Repository: "team/app", Tag: "release"},
		{Registry: "harbor.example:8443", Repository: "team/app", Tag: "release"},
		{Registry: "HARBOR.example", Repository: "team/app", Hash: "sha256:123"},
	}
	statuses, err := a.GetImagesScanStatus(context.Background(), images)
	require.Error(t, err)
	require.Len(t, statuses, len(images))
	for i, status := range statuses {
		require.Equal(t, images[i], status.ImageID)
		require.Equal(t, i == 1 || i == 3, status.IsScanAvailable)
	}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.Error(t, err)
	require.Len(t, reports, len(images))
	for i, report := range reports {
		require.Equal(t, images[i], report.ImageID)
		if i == 1 || i == 3 {
			require.Len(t, report.Vulnerabilities, 1)
			require.Equal(t, "CVE-local", report.Vulnerabilities[0].ID)
		} else {
			require.Empty(t, report.Vulnerabilities)
		}
	}
	require.Len(t, api.paths, 4)
}

func TestHarborIdentity_DigestPrecedenceAndNestedPathsAreUnchanged(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	image := ContainerImageIdentifier{Registry: "harbor.example", Repository: "team/backend/api", Tag: "release", Hash: "sha256:123"}
	_, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	_, err = a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Equal(t, []string{
		"/api/v2.0/projects/team/repositories/backend%252Fapi/artifacts/sha256:123?with_scan_overview=true",
		"/api/v2.0/projects/team/repositories/backend%252Fapi/artifacts/sha256:123/additions/vulnerabilities",
	}, api.paths)
}

func TestHarborIdentity_HTTPPipelineCannotMisattributeForeignFindings(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, "/additions/vulnerabilities") {
			_, _ = w.Write([]byte(`{"scanner":{"vulnerabilities":[{"id":"CVE-collision","severity":"Critical"}]}}`))
		} else {
			_, _ = w.Write([]byte(`{"scan_overview":{"scanner":{"scan_status":"Success"}}}`))
		}
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	api := &harborAPIWrapper{baseURL: server.URL, httpClient: server.Client()}
	a := &HarborAdaptor{host: host, client: api}
	foreign := ContainerImageIdentifier{Registry: "other.example", Repository: "team/app", Tag: "same-tag"}
	local := foreign
	local.Registry = host
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{foreign, local})
	require.ErrorContains(t, err, "does not match")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, "CVE-collision", reports[1].Vulnerabilities[0].ID)
	require.Equal(t, int32(1), hits.Load())
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{foreign, local})
	require.Error(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[1].IsScanAvailable)
	require.Equal(t, int32(2), hits.Load())
}

func TestHarborIdentity_LoginSetsRegistryBoundary(t *testing.T) {
	for _, credentials := range []RegistryCredentials{
		{}, {Token: "identity-test-only"}, {Username: "robot", Password: "test-password"},
	} {
		t.Run(fmt.Sprintf("token=%t/basic=%t", credentials.Token != "", credentials.Username != ""), func(t *testing.T) {
			var queries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2.0/systeminfo" {
					_, _ = w.Write([]byte(`{}`))
					return
				}
				queries.Add(1)
				_, _ = w.Write([]byte(`{"scanner":{"vulnerabilities":[]}}`))
			}))
			defer server.Close()
			a := NewHarborAdaptor()
			require.NoError(t, a.Login(context.Background(), server.URL, credentials))
			foreign := ContainerImageIdentifier{Registry: "other.example", Repository: "team/app", Tag: "release"}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{foreign})
			require.ErrorContains(t, err, "does not match")
			require.Empty(t, reports[0].Vulnerabilities)
			require.Zero(t, queries.Load())
		})
	}
}

func TestHarborIdentity_NoReferenceStillSkipsWithoutRequests(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	image := ContainerImageIdentifier{Registry: "other.example", Repository: "team/app"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Empty(t, reports[0].Status)
	require.Empty(t, api.paths)
}

func TestHarborIdentity_LocalProviderErrorsArePreserved(t *testing.T) {
	failed := errors.New("local scanner unavailable")
	api := &identityHarborAPI{call: func(string) ([]byte, error) { return nil, failed }}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	image := ContainerImageIdentifier{Registry: "harbor.example", Repository: "team/app", Tag: "release"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, failed)
	require.Equal(t, image, statuses[0].ImageID)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, failed)
	require.Equal(t, image, reports[0].ImageID)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Len(t, api.paths, 2)
}

func TestHarborIdentity_LocalTimestampAndJSONIdentityArePreserved(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	images := []ContainerImageIdentifier{
		{Registry: "harbor.example", Repository: "team/app", Hash: "sha256:123"},
		{Registry: "other.example", Repository: "team/app", Hash: "sha256:123"},
	}
	statuses, err := a.GetImagesScanStatus(context.Background(), images)
	require.Error(t, err)
	require.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), statuses[0].LastScanDate)
	require.True(t, statuses[1].LastScanDate.IsZero())
	raw, err := json.Marshal(statuses)
	require.NoError(t, err)
	var decoded []ContainerImageScanStatus
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, statuses, decoded)
	require.Equal(t, "other.example", decoded[1].ImageID.Registry)
	require.False(t, decoded[1].IsScanAvailable)
}

func TestHarborIdentity_EmptyHostKeepsInjectedClientCompatibility(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{client: api}
	image := ContainerImageIdentifier{Registry: "harbor.example", Repository: "team/app", Tag: "release"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
}

func TestHarborIdentity_MultipleFailuresAreNotLost(t *testing.T) {
	failed := errors.New("local request failed")
	api := &identityHarborAPI{call: func(string) ([]byte, error) { return nil, failed }}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	images := []ContainerImageIdentifier{
		{Registry: "other.example", Repository: "team/app", Tag: "release"},
		{Registry: "harbor.example", Repository: "team/app", Tag: "release"},
		{Registry: "harbor.example:8443", Repository: "team/app", Tag: "release"},
	}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorIs(t, err, failed)
	require.ErrorContains(t, err, "other.example")
	require.ErrorContains(t, err, "8443")
	require.Len(t, reports, 3)
	require.Len(t, api.paths, 1)
	for i, report := range reports {
		require.Equal(t, images[i], report.ImageID)
		require.Empty(t, report.Vulnerabilities)
	}
}

func TestHarborIdentity_ReloginMovesBoundaryToNewRegistry(t *testing.T) {
	servers := make([]*httptest.Server, 0, 2)
	for i := 0; i < 2; i++ {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		servers = append(servers, server)
		defer server.Close()
	}
	a := NewHarborAdaptor()
	require.NoError(t, a.Login(context.Background(), servers[0].URL, RegistryCredentials{}))
	old := ContainerImageIdentifier{Registry: strings.TrimPrefix(servers[0].URL, "http://"), Repository: "team/app", Tag: "release"}
	require.NoError(t, a.Login(context.Background(), servers[1].URL, RegistryCredentials{}))
	_, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{old})
	require.ErrorContains(t, err, "does not match")
	updated := old
	updated.Registry = strings.TrimPrefix(servers[1].URL, "http://")
	_, err = a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{updated})
	require.NoError(t, err)
}

func TestHarborIdentity_DifferentLocalPortsAreDifferentRegistries(t *testing.T) {
	var secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer second.Close()
	a := NewHarborAdaptor()
	require.NoError(t, a.Login(context.Background(), first.URL, RegistryCredentials{}))
	image := ContainerImageIdentifier{Registry: strings.TrimPrefix(second.URL, "http://"), Repository: "team/app", Tag: "release"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "does not match")
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "does not match")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Zero(t, secondHits.Load())
}

func TestHarborIdentity_RegistryValidationPrecedesRepositoryRequests(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	image := ContainerImageIdentifier{Registry: "other.example", Repository: "missing-project", Tag: "release"}
	_, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "does not match")
	_, err = a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "does not match")
	require.Empty(t, api.paths)
	image.Registry = "harbor.example"
	_, err = a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "expected project/repository")
	require.Empty(t, api.paths)
}

func TestHarborIdentity_MalformedLocalResponsesStillFail(t *testing.T) {
	for _, response := range []string{"not-json", "[1,2]", `{"scanner":{"vulnerabilities":"invalid"}}`} {
		t.Run(response, func(t *testing.T) {
			api := &identityHarborAPI{call: func(string) ([]byte, error) {
				return []byte(response), nil
			}}
			a := &HarborAdaptor{host: "harbor.example", client: api}
			image := ContainerImageIdentifier{Registry: "harbor.example", Repository: "team/app", Tag: "release"}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.Empty(t, reports[0].Vulnerabilities)
			require.Empty(t, reports[0].Status)
			require.Len(t, api.paths, 1)
		})
	}
}

func TestHarborIdentity_EmptyBatchesDoNotQueryProvider(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	statuses, err := a.GetImagesScanStatus(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, statuses)
	reports, err := a.GetImagesVulnerabilities(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, reports)
	require.Empty(t, api.paths)
}

func TestHarborIdentity_AuthorityParsingDoesNotDiscardPorts(t *testing.T) {
	for _, tc := range []struct{ input, expected string }{
		{"harbor.example", "harbor.example"},
		{"HARBOR.example:8443", "harbor.example:8443"},
		{"https://harbor.example:8443/", "harbor.example:8443"},
		{"http://harbor.example:8080/", "harbor.example:8080"},
		{"https://[2001:db8::1]:8443", "[2001:db8::1]:8443"},
		{"127.0.0.1:12345", "127.0.0.1:12345"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			actual, err := harborRegistryAuthority(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestHarborIdentity_InvalidAuthorityErrorsDoNotPrintCredentials(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	// Synthetic userinfo verifies that malformed-authority errors do not echo passwords.
	password := t.Name()
	image := ContainerImageIdentifier{Registry: "https://robot:" + password + "@harbor.example", Repository: "team/app", Tag: "release"}
	_, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.NotContains(t, err.Error(), password)
	require.Empty(t, api.paths)
}

func TestHarborIdentity_InvalidConfiguredAuthorityFailsClosed(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "https://harbor.example/not-a-registry", client: api}
	image := ContainerImageIdentifier{Registry: "harbor.example", Repository: "team/app", Tag: "release"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, api.paths)
}

func TestHarborIdentity_RejectForeignImage(t *testing.T) {
	api := &mockHarborAPI{responses: map[string][]byte{
		"/api/v2.0/projects/team/repositories/app/artifacts/release?with_scan_overview=true":   []byte(`{"scan_overview":{"scanner":{"scan_status":"Success"}}}`),
		"/api/v2.0/projects/team/repositories/app/artifacts/release/additions/vulnerabilities": []byte(`{"scanner":{"vulnerabilities":[{"id":"CVE-other-registry","severity":"Critical"}]}}`),
	}}
	a := &HarborAdaptor{client: api, host: "harbor.example"}
	image := ContainerImageIdentifier{Registry: "foreign.example", Repository: "team/app", Tag: "release"}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestHarborIdentity_SerializedReportsCannotAttributeLocalCVEsToForeignImage(t *testing.T) {
	api := &identityHarborAPI{}
	a := &HarborAdaptor{host: "harbor.example", client: api}
	images := []ContainerImageIdentifier{
		{Registry: "other.example", Repository: "team/app", Tag: "release"},
		{Registry: "harbor.example", Repository: "team/app", Tag: "release"},
	}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.Error(t, err)
	raw, err := json.Marshal(reports)
	require.NoError(t, err)
	var decoded []ContainerImageVulnerabilityReport
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded, 2)
	require.Equal(t, images[0], decoded[0].ImageID)
	require.Empty(t, decoded[0].Vulnerabilities)
	require.Empty(t, decoded[0].Status)
	require.Equal(t, images[1], decoded[1].ImageID)
	require.Equal(t, "CVE-local", decoded[1].Vulnerabilities[0].ID)
	require.Equal(t, ScanStatusScanned, decoded[1].Status)
}
