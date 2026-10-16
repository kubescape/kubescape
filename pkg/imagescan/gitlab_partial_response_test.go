package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitLabPartialResponse_KeepsCVEsFromErrorResponse(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": []byte(`{"data":{"project":{"vulnerabilities":{"nodes":[{"title":"CVE-available","severity":"HIGH","location":{"image":"registry.gitlab.com/team/project:release"}}]}}},"errors":[{"message":"optional field unavailable"}]}`)}}
	a := &GitlabAdaptor{client: api}
	image := ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/project", Tag: "release"}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorContains(t, err, "optional field unavailable")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-available", reports[0].Vulnerabilities[0].ID)
}

func partialGitLabImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/project", Tag: "release"}
}

func partialGitLabNode(id, image string) map[string]any {
	return map[string]any{
		"title": id, "severity": "HIGH", "description": "available finding",
		"location": map[string]any{"image": image},
		"links":    []any{map[string]any{"url": "https://example.com/advisory"}},
	}
}

func partialGitLabPage(t *testing.T, nodes []any, cursor string, failures ...string) []byte {
	t.Helper()
	errors := make([]any, 0, len(failures))
	for _, failure := range failures {
		errors = append(errors, map[string]any{"message": failure})
	}
	data, err := json.Marshal(map[string]any{
		"data": map[string]any{"project": map[string]any{"vulnerabilities": map[string]any{
			"nodes":    nodes,
			"pageInfo": map[string]any{"hasNextPage": cursor != "", "endCursor": cursor},
		}}},
		"errors": errors,
	})
	require.NoError(t, err)
	return data
}

func TestGitLabPartialResponse_PreservesEarlierAndCurrentPageFindings(t *testing.T) {
	location := "registry.gitlab.com/team/project:release"
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":          partialGitLabPage(t, []any{partialGitLabNode("CVE-first", location)}, "page-two"),
		"team/project_page-two": partialGitLabPage(t, []any{partialGitLabNode("CVE-second", location)}, "", "field unavailable"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "field unavailable")
	require.Len(t, reports[0].Vulnerabilities, 2)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-second", reports[0].Vulnerabilities[1].ID)
	require.Equal(t, 1, api.callCount["team/project_page-two"])
}

func TestGitLabPartialResponse_DoesNotContinueAfterExecutionError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")}, "unsafe-next", "partial result"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "partial result")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Zero(t, api.callCount["team/project_unsafe-next"])
	require.Equal(t, 1, api.callCount["team/project"])
}

func TestGitLabPartialResponse_ProjectCacheRetainsDataAndErrorForEachImage(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{
			partialGitLabNode("CVE-release", "registry.gitlab.com/team/project:release"),
			partialGitLabNode("CVE-other", "registry.gitlab.com/team/project:other"),
		}, "", "partial page"),
	}}
	first := partialGitLabImage()
	second := first
	second.Tag = "other"
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{first, second})
	require.ErrorContains(t, err, "partial page")
	require.Len(t, reports, 2)
	require.Equal(t, "CVE-release", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-other", reports[1].Vulnerabilities[0].ID)
	require.Equal(t, first, reports[0].ImageID)
	require.Equal(t, second, reports[1].ImageID)
	require.Equal(t, 1, api.callCount["team/project"])
}

func TestGitLabPartialResponse_ForeignImageFindingsAreStillExcluded(t *testing.T) {
	for _, image := range []string{
		"foreign.example/team/project:release",
		"registry.gitlab.com/team/project:other",
		"registry.gitlab.com/team/project-suffix:release",
		"registry.gitlab.com/other/project:release",
	} {
		t.Run(image, func(t *testing.T) {
			api := &mockGitlabAPI{responses: map[string][]byte{
				"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-foreign", image)}, "", "partial page"),
			}}
			reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
			require.Error(t, err)
			require.Empty(t, reports[0].Vulnerabilities)
			require.Empty(t, reports[0].Status)
		})
	}
}

func TestGitLabPartialResponse_DigestRemainsAuthoritative(t *testing.T) {
	image := partialGitLabImage()
	image.Hash = "sha256:123"
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{
			partialGitLabNode("CVE-digest", "registry.gitlab.com/team/project@sha256:123"),
			partialGitLabNode("CVE-wrong", "registry.gitlab.com/team/project@sha256:456"),
		}, "", "partial page"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-digest", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_NullProjectStillReturnsGraphQLError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": []byte(`{"data":{"project":null},"errors":[{"message":"permission denied"}]}`),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "permission denied")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_ErrorsWithoutDataAreNotClean(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": []byte(`{"errors":[{"message":"execution failed"}]}`),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "execution failed")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_NullConnectionDoesNotInventCVEs(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": []byte(`{"data":{"project":{"vulnerabilities":null}},"errors":[{"message":"connection unavailable"}]}`),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "connection unavailable")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_EmptyNodesStillReturnError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, nil, "", "nothing available"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "nothing available")
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_IncompleteNodesDoNotMatchRequestedImage(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{
			nil, map[string]any{"title": "CVE-unattributed", "location": nil},
			partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release"),
		}, "", "location field failed"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.Error(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-local", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_NormalizesSeverityWithoutLosingMetadata(t *testing.T) {
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"} {
		t.Run(severity, func(t *testing.T) {
			node := partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")
			node["severity"] = severity
			api := &mockGitlabAPI{responses: map[string][]byte{"team/project": partialGitLabPage(t, []any{node}, "", "field failed")}}
			reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
			require.Error(t, err)
			vuln := reports[0].Vulnerabilities[0]
			require.Equal(t, normalizeGitLabSeverity(severity), vuln.Severity)
			require.Equal(t, "available finding", vuln.Description)
			require.Equal(t, []string{"https://example.com/advisory"}, vuln.Links)
		})
	}
}

func TestGitLabPartialResponse_UnrelatedProjectContinuesAfterPartialError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":  partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "", "first failed"),
		"other/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-second", "registry.gitlab.com/other/project:release")}, ""),
	}}
	first := partialGitLabImage()
	second := first
	second.Repository = "other/project"
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{first, second})
	require.ErrorContains(t, err, "first failed")
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "CVE-second", reports[1].Vulnerabilities[0].ID)
	require.Equal(t, 1, api.callCount["other/project"])
}

func TestGitLabPartialResponse_TransportErrorStillPreservesEarlierPage(t *testing.T) {
	failure := errors.New("network failed")
	api := &mockGitlabAPI{
		responses: map[string][]byte{"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "next")},
		errors:    map[string]error{"team/project_next": failure},
	}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorIs(t, err, failure)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_MalformedLaterJSONStillPreservesEarlierPage(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":      partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "next"),
		"team/project_next": []byte(`{"data":`),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "parse vulnerability payload")
	require.Len(t, reports[0].Vulnerabilities, 1)
}

func TestGitLabPartialResponse_AllSuccessfulPagesRemainSuccessful(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":      partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "next"),
		"team/project_next": partialGitLabPage(t, []any{partialGitLabNode("CVE-second", "registry.gitlab.com/team/project:release")}, ""),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.NoError(t, err)
	require.Len(t, reports[0].Vulnerabilities, 2)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestGitLabPartialResponse_ErrorStillPresentAfterJSONSerialization(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")}, "", "partial page"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "partial page")
	raw, marshalErr := json.Marshal(reports)
	require.NoError(t, marshalErr)
	var decoded []ContainerImageVulnerabilityReport
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, reports, decoded)
	require.Contains(t, string(raw), "CVE-local")
}

func TestGitLabPartialResponse_EmptyBatchDoesNotQuery(t *testing.T) {
	api := &mockGitlabAPI{}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, reports)
	require.Empty(t, api.callCount)
}

func TestGitLabPartialResponse_RecoveryOnLaterCallDoesNotRetainOldError(t *testing.T) {
	node := partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": partialGitLabPage(t, []any{node}, "", "temporary")}}
	a := &GitlabAdaptor{client: api}
	before, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.Error(t, err)
	api.responses["team/project"] = partialGitLabPage(t, []any{node}, "")
	after, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, 2, api.callCount["team/project"])
}

func TestGitLabPartialResponse_SeveralErrorsKeepFirstErrorCompatibility(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")}, "", "first error", "second error"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "first error")
	require.Len(t, reports[0].Vulnerabilities, 1)
}

func TestGitLabPartialResponse_ParentProjectResolutionKeepsImageRepository(t *testing.T) {
	image := partialGitLabImage()
	image.Repository = "team/project/nested"
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-nested", "registry.gitlab.com/team/project/nested:release")}, "", "partial page"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, image, reports[0].ImageID)
	require.Equal(t, "CVE-nested", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_LargePartialPageDoesNotDropNodes(t *testing.T) {
	nodes := make([]any, 100)
	for i := range nodes {
		nodes[i] = partialGitLabNode(fmt.Sprintf("CVE-%d", i), "registry.gitlab.com/team/project:release")
	}
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": partialGitLabPage(t, nodes, "", "partial page")}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.Error(t, err)
	require.Len(t, reports[0].Vulnerabilities, len(nodes))
	require.Equal(t, "CVE-99", reports[0].Vulnerabilities[99].ID)
}

func TestGitLabPartialResponse_CancellationErrorRemainsVisible(t *testing.T) {
	api := projectLookupAPI{call: func(ctx context.Context, query string, _ map[string]interface{}) ([]byte, error) {
		if strings.Contains(query, "ResolveRegistryProject") {
			return projectLookupPayload(t, "team/project"), nil
		}
		return nil, context.Canceled
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_HTTPPipelineKeepsPartialVulnerabilityData(t *testing.T) {
	for _, kind := range []string{"token", "anonymous"} {
		t.Run(kind, func(t *testing.T) {
			var registry string
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct{ Query string }
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.Contains(body.Query, "currentUser"):
					_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"fixture"}}}`))
				case strings.Contains(body.Query, "ResolveRegistryProject"):
					_, _ = w.Write(projectLookupPayload(t, "team/project"))
				default:
					calls++
					_, _ = w.Write(partialGitLabPage(t, []any{partialGitLabNode("CVE-http", registry+"/team/project:release")}, "", "optional field failed"))
				}
			}))
			defer server.Close()
			address, err := url.Parse(server.URL)
			require.NoError(t, err)
			registry = address.Host
			a := NewGitlabAdaptor()
			credentials := RegistryCredentials{}
			if kind == "token" {
				credentials.Token = t.Name()
			}
			loginErr := a.Login(context.Background(), server.URL, credentials)
			if kind == "anonymous" {
				require.ErrorContains(t, loginErr, "requires a personal or project access token")
				require.Zero(t, calls)
				return
			}
			require.NoError(t, loginErr)
			image := partialGitLabImage()
			image.Registry = registry
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.ErrorContains(t, err, "optional field failed")
			require.Len(t, reports[0].Vulnerabilities, 1)
			require.Equal(t, "CVE-http", reports[0].Vulnerabilities[0].ID)
			require.Equal(t, 1, calls)
		})
	}
}

func TestGitLabPartialResponse_AllProjectErrorsRemainInBatchError(t *testing.T) {
	api := &mockGitlabAPI{responses: make(map[string][]byte)}
	var images []ContainerImageIdentifier
	for i := 0; i < 3; i++ {
		image := partialGitLabImage()
		image.Repository = fmt.Sprintf("team/project%d", i)
		images = append(images, image)
		api.responses[image.Repository] = partialGitLabPage(t, []any{
			partialGitLabNode(fmt.Sprintf("CVE-%d", i), image.Registry+"/"+image.Repository+":"+image.Tag),
		}, "", fmt.Sprintf("error-%d", i))
	}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), images)
	require.Error(t, err)
	require.Len(t, reports, 3)
	for i := range images {
		require.Contains(t, err.Error(), fmt.Sprintf("error-%d", i))
		require.Equal(t, images[i], reports[i].ImageID)
		require.Len(t, reports[i].Vulnerabilities, 1)
		require.Equal(t, fmt.Sprintf("CVE-%d", i), reports[i].Vulnerabilities[0].ID)
	}
}

func TestGitLabPartialResponse_NullProjectOnLaterPageKeepsEarlierCVEs(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":      partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "next"),
		"team/project_next": []byte(`{"data":{"project":null},"errors":[{"message":"project disappeared"}]}`),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "project disappeared")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-first", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_RepeatedImagesDoNotDuplicatePageNodes(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")}, "", "partial page"),
	}}
	image := partialGitLabImage()
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image, image, image})
	require.Error(t, err)
	require.Len(t, reports, 3)
	for _, report := range reports {
		require.Len(t, report.Vulnerabilities, 1)
	}
	require.Equal(t, 1, api.callCount["team/project"])
}

func TestGitLabPartialResponse_SuccessfulEmptyProjectRemainsUnknown(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": partialGitLabPage(t, nil, "")}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.NoError(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
	require.Equal(t, partialGitLabImage(), reports[0].ImageID)
}

func TestGitLabPartialResponse_ErrorPageCursorDoesNotOverrideExecutionError(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project":      partialGitLabPage(t, []any{partialGitLabNode("CVE-first", "registry.gitlab.com/team/project:release")}, "same"),
		"team/project_same": partialGitLabPage(t, []any{partialGitLabNode("CVE-second", "registry.gitlab.com/team/project:release")}, "same", "execution error"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "execution error")
	require.NotContains(t, err.Error(), "repeated cursor")
	require.Len(t, reports[0].Vulnerabilities, 2)
}

func TestGitLabPartialResponse_UninitializedClientStillFails(t *testing.T) {
	reports, err := NewGitlabAdaptor().GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "not initialized")
	require.Nil(t, reports)
}

func TestGitLabPartialResponse_NestedRepositoryDoesNotReceiveSiblingCVEs(t *testing.T) {
	image := partialGitLabImage()
	image.Repository = "team/project/nested"
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{
			partialGitLabNode("CVE-sibling", "registry.gitlab.com/team/project/sibling:release"),
			partialGitLabNode("CVE-nested", "registry.gitlab.com/team/project/nested:release"),
		}, "", "partial page"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.Error(t, err)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-nested", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabPartialResponse_MixedMatchingAndMissingLocationNodes(t *testing.T) {
	local := partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")
	missing := map[string]any{"title": "CVE-missing"}
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{missing, local, missing}, "", "location unavailable"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "location unavailable")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, partialGitLabImage(), reports[0].ImageID)
}

func TestGitLabPartialResponse_ResponseErrorDoesNotMarkUnmatchedImageScanned(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{
		"team/project": partialGitLabPage(t, []any{partialGitLabNode("CVE-other", "registry.gitlab.com/team/project:other")}, "", "partial page"),
	}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.Error(t, err)
	require.Empty(t, reports[0].Status)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestGitLabPartialResponse_InvalidFirstPageIsNotUsablePartialData(t *testing.T) {
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": []byte(`{"data":{"project":`)}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "parse vulnerability payload")
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabPartialResponse_NodeWithFailedTitleIsNotAnIdentifiedCVE(t *testing.T) {
	missing := partialGitLabNode("", "registry.gitlab.com/team/project:release")
	local := partialGitLabNode("CVE-local", "registry.gitlab.com/team/project:release")
	api := &mockGitlabAPI{responses: map[string][]byte{"team/project": partialGitLabPage(t, []any{missing, local}, "", "title unavailable")}}
	reports, err := (&GitlabAdaptor{client: api}).GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{partialGitLabImage()})
	require.ErrorContains(t, err, "title unavailable")
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "CVE-local", reports[0].Vulnerabilities[0].ID)
}
