package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectLookupAPI struct {
	call func(context.Context, string, map[string]interface{}) ([]byte, error)
}

func (api projectLookupAPI) DoGraphQL(ctx context.Context, query string, vars map[string]interface{}) ([]byte, error) {
	return api.call(ctx, query, vars)
}

func projectLookupPayload(t *testing.T, path string) []byte {
	t.Helper()
	var project any
	if path != "" {
		project = map[string]any{"fullPath": path}
	}
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"project": project}})
	require.NoError(t, err)
	return raw
}

func TestGitLabProjectCandidates_KeepRootAndBoundOptionalPath(t *testing.T) {
	for _, tc := range []struct {
		repository string
		want       []string
	}{
		{
			repository: "team/project",
			want:       []string{"team/project"},
		},
		{
			repository: "team/project/app",
			want:       []string{"team/project/app", "team/project"},
		},
		{
			repository: "team/project/images/app",
			want:       []string{"team/project/images/app", "team/project/images", "team/project"},
		},
		{
			repository: "team/subgroup/project",
			want:       []string{"team/subgroup/project", "team/subgroup"},
		},
		{
			repository: "team/subgroup/deep/project/images/app",
			want: []string{
				"team/subgroup/deep/project/images/app",
				"team/subgroup/deep/project/images",
				"team/subgroup/deep/project",
			},
		},
		{
			repository: "/team/project",
			want:       []string{"team/project"},
		},
	} {
		t.Run(tc.repository, func(t *testing.T) {
			got, err := gitLabProjectCandidates(tc.repository)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGitLabProjectCandidates_RejectMalformedPaths(t *testing.T) {
	for _, repository := range []string{
		"", "project", "/project", "team//project", "team/project/",
		"team/../project", "team/./project", "team/project:tag",
		"team/project@sha256:x", "team/project\n", "team /project",
		"//team/project",
	} {
		t.Run(repository, func(t *testing.T) {
			got, err := gitLabProjectCandidates(repository)
			require.Error(t, err)
			require.Empty(t, got)
		})
	}
}

func TestGitLabResolveRegistryProject_RootAndOptionalPaths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		repository string
		project    string
		wantCalls  []string
	}{
		{
			name:       "root image",
			repository: "team/project",
			project:    "team/project",
			wantCalls:  []string{"team/project"},
		},
		{
			name:       "one image component",
			repository: "team/project/app",
			project:    "team/project",
			wantCalls:  []string{"team/project/app", "team/project"},
		},
		{
			name:       "two image components",
			repository: "team/project/images/app",
			project:    "team/project",
			wantCalls:  []string{"team/project/images/app", "team/project/images", "team/project"},
		},
		{
			name:       "subgroup root image",
			repository: "team/subgroup/project",
			project:    "team/subgroup/project",
			wantCalls:  []string{"team/subgroup/project"},
		},
		{
			name:       "subgroups with two image components",
			repository: "team/subgroup/deep/project/images/app",
			project:    "team/subgroup/deep/project",
			wantCalls: []string{
				"team/subgroup/deep/project/images/app",
				"team/subgroup/deep/project/images",
				"team/subgroup/deep/project",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			adaptor := &GitlabAdaptor{client: projectLookupAPI{call: func(_ context.Context, query string, vars map[string]interface{}) ([]byte, error) {
				require.Contains(t, query, "ResolveRegistryProject")
				candidate := vars["fullPath"].(string)
				calls = append(calls, candidate)
				if candidate == tc.project {
					return projectLookupPayload(t, tc.project), nil
				}
				return projectLookupPayload(t, ""), nil
			}}}
			cache := make(map[string]gitLabProjectResolution)
			for i := 0; i < 2; i++ {
				path, err := adaptor.resolveRegistryProject(context.Background(), tc.repository, cache)
				require.NoError(t, err)
				require.Equal(t, tc.project, path)
			}
			require.Equal(t, tc.wantCalls, calls, "repeat images reuse project discovery")
		})
	}
}

func TestGitLabResolveRegistryProject_ErrorsDoNotGuessAParent(t *testing.T) {
	transportError := errors.New("transport unavailable")
	for _, tc := range []struct {
		name      string
		payload   []byte
		err       error
		wantError string
	}{
		{
			name:      "transport",
			err:       transportError,
			wantError: "transport unavailable",
		},
		{
			name:      "malformed JSON",
			payload:   []byte("not JSON"),
			wantError: "decode gitlab project",
		},
		{
			name:      "GraphQL forbidden",
			payload:   []byte(`{"errors":[{"message":"Forbidden"}]}`),
			wantError: "Forbidden",
		},
		{
			name:      "unexpected project identity",
			payload:   projectLookupPayload(t, "other/project"),
			wantError: "unexpected path",
		},
		{
			name:      "project without path",
			payload:   []byte(`{"data":{"project":{}}}`),
			wantError: "unexpected path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			adaptor := &GitlabAdaptor{client: projectLookupAPI{call: func(_ context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
				calls++
				return tc.payload, tc.err
			}}}
			cache := make(map[string]gitLabProjectResolution)
			for i := 0; i < 2; i++ {
				path, err := adaptor.resolveRegistryProject(context.Background(), "team/project/app", cache)
				require.ErrorContains(t, err, tc.wantError)
				require.Empty(t, path)
				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}
			}
			require.Equal(t, 1, calls)
		})
	}
}

func TestGitLabResolveRegistryProject_AbsentProjectHasBoundedRequests(t *testing.T) {
	calls := 0
	adaptor := &GitlabAdaptor{client: projectLookupAPI{call: func(_ context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
		calls++
		return projectLookupPayload(t, ""), nil
	}}}
	path, err := adaptor.resolveRegistryProject(context.Background(), "a/b/c/d/e/f/g", make(map[string]gitLabProjectResolution))
	require.ErrorContains(t, err, "project not found or permission denied")
	require.Empty(t, path)
	require.Equal(t, 3, calls)
}

func TestGitLabAdaptor_ProjectResolutionStatusAndFindings(t *testing.T) {
	for _, repository := range []string{
		"team/project",
		"team/project/app",
		"team/project/images/app",
		"team/subgroup/project",
		"team/subgroup/project/images/app",
	} {
		t.Run(repository, func(t *testing.T) {
			project := "team/project"
			if strings.Contains(repository, "subgroup") {
				project = "team/subgroup/project"
			}
			images := []ContainerImageIdentifier{
				{Registry: "registry.gitlab.com", Repository: repository, Tag: "v1"},
				{Registry: "registry.gitlab.com", Repository: repository, Tag: "v2"},
			}
			lookupCalls, findingCalls := 0, 0
			adaptor := &GitlabAdaptor{client: projectLookupAPI{call: func(_ context.Context, query string, vars map[string]interface{}) ([]byte, error) {
				path := vars["fullPath"].(string)
				if strings.Contains(query, "ResolveRegistryProject") {
					lookupCalls++
					if path == project {
						return projectLookupPayload(t, project), nil
					}
					return projectLookupPayload(t, ""), nil
				}
				findingCalls++
				require.Equal(t, project, path, "never query findings on a guessed subgroup")
				if vars["after"] != nil {
					require.Equal(t, "page2", vars["after"])
				}
				nodes := []any{map[string]any{
					"title":    "CVE-v1",
					"location": map[string]any{"image": "registry.gitlab.com/" + repository + ":v1"},
				}}
				next := "page2"
				if vars["after"] != nil {
					nodes = []any{map[string]any{
						"title":    "CVE-v2",
						"location": map[string]any{"image": "registry.gitlab.com/" + repository + ":v2"},
					}}
					next = ""
				}
				return json.Marshal(map[string]any{"data": map[string]any{"project": map[string]any{
					"vulnerabilities": map[string]any{
						"nodes":    nodes,
						"pageInfo": map[string]any{"hasNextPage": next != "", "endCursor": next},
					},
				}}})
			}}}
			statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
			require.NoError(t, err)
			require.Len(t, statuses, 2)
			for _, status := range statuses {
				require.True(t, status.IsScanAvailable)
			}
			callsPerResolution := lookupCalls
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
			require.NoError(t, err)
			require.Len(t, reports, 2)
			for i, report := range reports {
				require.Equal(t, images[i], report.ImageID)
				require.Equal(t, ScanStatusScanned, report.Status)
				require.Len(t, report.Vulnerabilities, 1)
				require.Equal(t, []string{"CVE-v1", "CVE-v2"}[i], report.Vulnerabilities[0].ID)
			}
			require.Equal(t, callsPerResolution*2, lookupCalls)
			require.Equal(t, 3, findingCalls, "one status request plus two findings pages")
		})
	}
}

func TestGitLabResolveRegistryProject_CancellationIsPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	adaptor := &GitlabAdaptor{client: projectLookupAPI{call: func(ctx context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
		calls++
		return nil, ctx.Err()
	}}}
	path, err := adaptor.resolveRegistryProject(ctx, "team/project/app", make(map[string]gitLabProjectResolution))
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, path)
	require.Equal(t, 1, calls, "cancellation must not trigger parent-path probing")
}
