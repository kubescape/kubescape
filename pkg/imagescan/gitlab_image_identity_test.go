package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitLabImageIdentity_DigestIsAuthoritative(t *testing.T) {
	image := ContainerImageIdentifier{
		Registry:   "registry.gitlab.com",
		Repository: "team/project/app",
		Tag:        "release",
		Hash:       "sha256:current",
	}
	for _, tc := range []struct {
		name     string
		location string
		want     bool
	}{
		{
			name:     "exact digest",
			location: "registry.gitlab.com/team/project/app@sha256:current",
			want:     true,
		},
		{
			name:     "repository-only digest",
			location: "team/project/app@sha256:current",
			want:     true,
		},
		{
			name:     "tag and matching digest",
			location: "registry.gitlab.com/team/project/app:release@sha256:current",
			want:     true,
		},
		{
			name:     "another tag with same content",
			location: "registry.gitlab.com/team/project/app:old-tag@sha256:current",
			want:     true,
		},
		{
			name:     "mutable tag alone does not prove digest",
			location: "registry.gitlab.com/team/project/app:release",
		},
		{
			name:     "same tag attached to old content",
			location: "registry.gitlab.com/team/project/app:release@sha256:old",
		},
		{
			name:     "wrong digest without tag",
			location: "registry.gitlab.com/team/project/app@sha256:old",
		},
		{
			name:     "different registry",
			location: "mirror.example.com/team/project/app@sha256:current",
		},
		{
			name:     "repository suffix is not identity",
			location: "registry.gitlab.com/other/team/project/app@sha256:current",
		},
		{
			name:     "lookalike registry suffix",
			location: "evil.registry.gitlab.com/team/project/app@sha256:current",
		},
		{
			name:     "different repository name",
			location: "registry.gitlab.com/team/project/webapp@sha256:current",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, imageMatches(tc.location, image))
		})
	}
}

func TestGitLabImageIdentity_TagOnlyAndRegistryPorts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		image    ContainerImageIdentifier
		location string
		want     bool
	}{
		{
			name:     "tag-only qualified",
			image:    ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "latest"},
			location: "registry.gitlab.com/team/app:latest",
			want:     true,
		},
		{
			name:     "tag-only repository-only",
			image:    ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "latest"},
			location: "team/app:latest",
			want:     true,
		},
		{
			name:     "tag-only version differs",
			image:    ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "latest"},
			location: "registry.gitlab.com/team/app:old",
		},
		{
			name:     "registry port is preserved",
			image:    ContainerImageIdentifier{Registry: "registry.example.com:5050", Repository: "team/app", Tag: "latest"},
			location: "registry.example.com:5050/team/app:latest",
			want:     true,
		},
		{
			name:     "different registry port",
			image:    ContainerImageIdentifier{Registry: "registry.example.com:5050", Repository: "team/app", Tag: "latest"},
			location: "registry.example.com:5051/team/app:latest",
		},
		{
			name:     "localhost registry",
			image:    ContainerImageIdentifier{Registry: "localhost:5050", Repository: "team/app", Hash: "sha256:x"},
			location: "localhost:5050/team/app@sha256:x",
			want:     true,
		},
		{
			name:     "no requested version",
			image:    ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/app"},
			location: "registry.gitlab.com/team/app:latest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, imageMatches(tc.location, tc.image))
		})
	}
}

func TestGitLabImageIdentity_LegacyRegistrylessInputs(t *testing.T) {
	image := ContainerImageIdentifier{Repository: "team/project/app", Tag: "v1"}
	for _, tc := range []struct {
		location string
		want     bool
	}{
		{location: "team/project/app:v1", want: true},
		{location: "registry.gitlab.com/team/project/app:v1", want: true},
		{location: "registry.example.com:5050/team/project/app:v1", want: true},
		{location: "localhost/team/project/app:v1", want: true},
		{location: "other/team/project/app:v1"},
		{location: "registry.gitlab.com/other/team/project/app:v1"},
		{location: "team/project/other-app:v1"},
	} {
		t.Run(tc.location, func(t *testing.T) {
			require.Equal(t, tc.want, imageMatches(tc.location, image))
		})
	}
}

func TestGitLabImageIdentity_MalformedLocationsDoNotMatch(t *testing.T) {
	image := ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "v1", Hash: "sha256:x"}
	for _, location := range []string{
		"",
		"https://registry.gitlab.com/team/app@sha256:x",
		" registry.gitlab.com/team/app@sha256:x",
		"registry.gitlab.com/team/app@sha256:x\n",
		"registry.gitlab.com/team/app@",
		"registry.gitlab.com/team/app@sha256:x@sha256:x",
		"registry.gitlab.com/team/app:@sha256:x",
		"registry.gitlab.com/team/app",
		"registry.gitlab.com//team/app@sha256:x",
	} {
		t.Run(location, func(t *testing.T) {
			require.False(t, imageMatches(location, image))
		})
	}
	require.False(t, imageMatches("registry.gitlab.com/:v1", ContainerImageIdentifier{Tag: "v1"}))
}

type identityGitLabAPI struct {
	call func(string, map[string]interface{}) ([]byte, error)
}

func (api identityGitLabAPI) DoGraphQL(_ context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	if strings.Contains(query, "ResolveRegistryProject") {
		// Discovery and vulnerability fetching are separate API operations.
		// These fixtures all belong to team/project, regardless of image path.
		if variables["fullPath"] == "team/project" {
			return []byte(`{"data":{"project":{"fullPath":"team/project"}}}`), nil
		}
		return []byte(`{"data":{"project":null}}`), nil
	}
	return api.call(query, variables)
}

func identityPayload(t *testing.T, locations []string, next string) []byte {
	t.Helper()
	nodes := make([]map[string]any, 0, len(locations))
	for _, location := range locations {
		nodes = append(nodes, map[string]any{
			"title":    location,
			"severity": "HIGH",
			"location": map[string]any{"image": location},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"data": map[string]any{"project": map[string]any{
			"vulnerabilities": map[string]any{
				"nodes":    nodes,
				"pageInfo": map[string]any{"hasNextPage": next != "", "endCursor": next},
			},
		}},
	})
	require.NoError(t, err)
	return raw
}

func TestGitLabImageIdentity_CachedProjectDoesNotMixImages(t *testing.T) {
	requested := []ContainerImageIdentifier{
		{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "release", Hash: "sha256:new"},
		{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "release", Hash: "sha256:old"},
		{Registry: "mirror.example.com", Repository: "team/project/app", Hash: "sha256:new"},
		{Registry: "registry.gitlab.com", Repository: "team/project/other", Tag: "v1"},
	}
	locations := []string{
		"registry.gitlab.com/team/project/app:release",
		"registry.gitlab.com/team/project/app@sha256:new",
		"registry.gitlab.com/team/project/app@sha256:old",
		"mirror.example.com/team/project/app@sha256:new",
		"registry.gitlab.com/other/team/project/app@sha256:new",
		"registry.gitlab.com/team/project/other:v1",
	}
	calls := 0
	adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(_ string, vars map[string]interface{}) ([]byte, error) {
		calls++
		require.Equal(t, "team/project", vars["fullPath"])
		if vars["after"] == nil {
			return identityPayload(t, locations[:3], "second"), nil
		}
		require.Equal(t, "second", vars["after"])
		return identityPayload(t, locations[3:], ""), nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), requested)
	require.NoError(t, err)
	require.Len(t, reports, len(requested))
	require.Equal(t, 2, calls, "pagination is shared by project, filtering is per image")
	for i, want := range []string{locations[1], locations[2], locations[3], locations[5]} {
		require.Equal(t, requested[i], reports[i].ImageID)
		require.Equal(t, ScanStatusScanned, reports[i].Status)
		require.Len(t, reports[i].Vulnerabilities, 1)
		require.Equal(t, want, reports[i].Vulnerabilities[0].ID)
	}
}

func TestGitLabImageIdentity_PartialResultsKeepExactMatching(t *testing.T) {
	image := ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "release", Hash: "sha256:new"}
	fetchError := errors.New("second page unavailable")
	adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(_ string, vars map[string]interface{}) ([]byte, error) {
		if vars["after"] != nil {
			return nil, fetchError
		}
		return identityPayload(t, []string{
			"registry.gitlab.com/team/project/app:release",
			"registry.gitlab.com/team/project/app@sha256:new",
		}, "second"), nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, fetchError)
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 1)
	require.Equal(t, "registry.gitlab.com/team/project/app@sha256:new", reports[0].Vulnerabilities[0].ID)
}

func TestGitLabImageIdentity_UnmatchedFindingsDoNotMarkImageScanned(t *testing.T) {
	image := ContainerImageIdentifier{
		Registry:   "registry.gitlab.com",
		Repository: "team/project/app",
		Tag:        "release",
		Hash:       "sha256:new",
	}
	adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(_ string, _ map[string]interface{}) ([]byte, error) {
		return identityPayload(t, []string{
			"registry.gitlab.com/team/project/app:release",
			"other.example.com/team/project/app@sha256:new",
			"registry.gitlab.com/other/team/project/app@sha256:new",
		}, ""), nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, image, reports[0].ImageID)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status, "unrelated project findings must not certify the requested image")
}

func TestGitLabImageIdentity_DigestReportsDoNotDependOnInputTag(t *testing.T) {
	locations := []string{
		"registry.gitlab.com/team/project/app:v1@sha256:content",
		"registry.gitlab.com/team/project/app:v2@sha256:content",
		"registry.gitlab.com/team/project/app:v3@sha256:other",
	}
	for _, tag := range []string{"", "v1", "v2", "v3"} {
		t.Run(tag, func(t *testing.T) {
			image := ContainerImageIdentifier{
				Registry:   "registry.gitlab.com",
				Repository: "team/project/app",
				Tag:        tag,
				Hash:       "sha256:content",
			}
			adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(_ string, _ map[string]interface{}) ([]byte, error) {
				return identityPayload(t, locations, ""), nil
			}}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Len(t, reports, 1)
			require.Len(t, reports[0].Vulnerabilities, 2)
			require.Equal(t, locations[0], reports[0].Vulnerabilities[0].ID)
			require.Equal(t, locations[1], reports[0].Vulnerabilities[1].ID)
		})
	}
}

func TestGitLabImageIdentity_EmptyProjectFindingsRemainEmpty(t *testing.T) {
	image := ContainerImageIdentifier{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "v1"}
	adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(_ string, _ map[string]interface{}) ([]byte, error) {
		return identityPayload(t, nil, ""), nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Empty(t, reports[0].Status)
}

func TestGitLabImageIdentity_RegistrylessLocationKeepsDigestIsolation(t *testing.T) {
	images := []ContainerImageIdentifier{
		{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "release", Hash: "sha256:one"},
		{Registry: "registry.gitlab.com", Repository: "team/project/app", Tag: "release", Hash: "sha256:two"},
	}
	adaptor := &GitlabAdaptor{client: identityGitLabAPI{call: func(string, map[string]interface{}) ([]byte, error) {
		return identityPayload(t, []string{
			"team/project/app:release@sha256:one",
			"team/project/app:release@sha256:two",
			"team/project/app:release",
		}, ""), nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, 2)
	for i, report := range reports {
		require.Equal(t, images[i], report.ImageID)
		require.Len(t, report.Vulnerabilities, 1)
		require.Equal(t, "team/project/app:release@"+images[i].Hash, report.Vulnerabilities[0].ID)
	}
}
