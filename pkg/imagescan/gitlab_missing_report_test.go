package imagescan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitLabMissingVulnerabilityConnectionReturnsError(t *testing.T) {
	for _, payload := range []string{
		`{"data":{"project":{}}}`,
		`{"data":{"project":{"vulnerabilities":null}}}`,
	} {
		for _, operation := range []string{"status", "vulnerabilities"} {
			t.Run(operation+"/"+payload, func(t *testing.T) {
				api := &mockGitlabAPI{responses: map[string][]byte{"team/project": []byte(payload)}}
				adaptor := &GitlabAdaptor{client: api}
				image := partialGitLabImage()
				// Both images share the project cache; the error must reach the caller
				// even when a cached result is used for a later image.
				other := image
				other.Tag = "other"
				images := []ContainerImageIdentifier{image, other}
				if operation == "status" {
					results, err := adaptor.GetImagesScanStatus(context.Background(), images)
					require.ErrorContains(t, err, "missing vulnerability connection")
					require.Len(t, results, 2)
					for i, result := range results {
						require.Equal(t, images[i], result.ImageID)
						require.False(t, result.IsScanAvailable)
					}
				} else {
					results, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
					require.ErrorContains(t, err, "missing vulnerability connection")
					require.Len(t, results, 2)
					for i, result := range results {
						require.Equal(t, images[i], result.ImageID)
						require.Empty(t, result.Vulnerabilities)
						require.Empty(t, result.Status)
					}
				}
				require.Equal(t, 1, api.callCount["team/project"])
			})
		}
	}
}

func TestGitLabMissingLaterConnectionPreservesEarlierFindings(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":      partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "next"),
		"team/project_next": []byte(`{"data":{"project":{"vulnerabilities":null}}}`),
	}}
	image := partialGitLabImage()
	results, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image, image})
	require.ErrorContains(t, err, "missing vulnerability connection")
	require.Len(t, results, 2)
	for _, report := range results {
		require.Len(t, report.Vulnerabilities, 1)
		require.Equal(t, "CVE-first", report.Vulnerabilities[0].ID)
	}
	require.Equal(t, 1, api.callCount["team/project"])
	require.Equal(t, 1, api.callCount["team/project_next"])
}

func TestGitLabEmptyVulnerabilityConnectionIsNotMissing(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": []byte(`{"data":{"project":{"vulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`),
	}}
	adaptor := &GitlabAdaptor{client: api}
	images := []ContainerImageIdentifier{partialGitLabImage()}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.NoError(t, err)
	require.True(t, statuses[0].IsScanAvailable)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestGitLabMissingConnectionKeepsExecutionError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": []byte(`{"data":{"project":{"vulnerabilities":null}},"errors":[{"message":"permission denied"}]}`),
	}}
	adaptor := &GitlabAdaptor{client: api}
	images := []ContainerImageIdentifier{partialGitLabImage()}
	_, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "permission denied")
	_, err = adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "permission denied")
}

func TestGitLabMissingConnectionThroughHTTP(t *testing.T) {
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer report-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(request.Query, "currentUser"):
			fmt.Fprint(w, `{"data":{"currentUser":{"username":"contributor"}}}`)
		case strings.Contains(request.Query, "ResolveRegistryProject"):
			fmt.Fprint(w, `{"data":{"project":{"fullPath":"team/project"}}}`)
		default:
			queries++
			fmt.Fprint(w, `{"data":{"project":{"vulnerabilities":null}}}`)
		}
	}))
	defer server.Close()
	adaptor := NewGitlabAdaptor()
	require.NoError(t, adaptor.Login(context.Background(), server.URL, RegistryCredentials{Token: "report-token"}))
	images := []ContainerImageIdentifier{partialGitLabImage()}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "missing vulnerability connection")
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "missing vulnerability connection")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, 2, queries)
}

func TestGitLabMissingConnectionDoesNotDiscardOtherProjects(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":  []byte(`{"data":{"project":{"vulnerabilities":null}}}`),
		"other/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-retained", "registry.gitlab.com/other/project:release")}, ""),
	}}
	first := partialGitLabImage()
	second := first
	second.Repository = "other/project"
	adaptor := &GitlabAdaptor{client: api}
	images := []ContainerImageIdentifier{first, second}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.Error(t, err)
	require.Len(t, statuses, 2)
	require.False(t, statuses[0].IsScanAvailable)
	require.True(t, statuses[1].IsScanAvailable)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.Error(t, err)
	require.Len(t, reports, 2)
	require.Equal(t, first, reports[0].ImageID)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, second, reports[1].ImageID)
	require.Len(t, reports[1].Vulnerabilities, 1)
	require.Equal(t, "CVE-retained", reports[1].Vulnerabilities[0].ID)
}
