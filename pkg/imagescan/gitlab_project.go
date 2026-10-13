package imagescan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// GitLab allows the project's own registry repository and up to two optional
// image-path components. Subgroups make the boundary ambiguous, so resolve it
// using the project API rather than unconditionally removing the last segment.
func gitLabProjectCandidates(repository string) ([]string, error) {
	repository = strings.TrimPrefix(repository, "/")
	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid gitlab repository format: expected namespace/project, got %s", repository)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, " :@\t\r\n") {
			return nil, fmt.Errorf("invalid gitlab repository path %q", repository)
		}
	}
	candidates := make([]string, 0, 3)
	for removed := 0; removed <= 2 && len(parts)-removed >= 2; removed++ {
		candidates = append(candidates, strings.Join(parts[:len(parts)-removed], "/"))
	}
	return candidates, nil
}

type gitLabProjectResolution struct {
	path string
	err  error
}

func (a *GitlabAdaptor) resolveRegistryProject(ctx context.Context, repository string, cache map[string]gitLabProjectResolution) (string, error) {
	if result, ok := cache[repository]; ok {
		return result.path, result.err
	}
	path, err := a.lookupRegistryProject(ctx, repository)
	cache[repository] = gitLabProjectResolution{path: path, err: err}
	return path, err
}

func (a *GitlabAdaptor) lookupRegistryProject(ctx context.Context, repository string) (string, error) {
	candidates, err := gitLabProjectCandidates(repository)
	if err != nil {
		return "", err
	}
	const query = `query ResolveRegistryProject($fullPath: ID!) { project(fullPath: $fullPath) { fullPath } }`
	for _, candidate := range candidates {
		data, err := a.client.DoGraphQL(ctx, query, map[string]interface{}{"fullPath": candidate})
		if err != nil {
			return "", fmt.Errorf("resolve gitlab project %s: %w", candidate, err)
		}
		var response struct {
			Data struct {
				Project *struct {
					FullPath string `json:"fullPath"`
				} `json:"project"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return "", fmt.Errorf("decode gitlab project %s: %w", candidate, err)
		}
		if len(response.Errors) > 0 {
			return "", fmt.Errorf("resolve gitlab project %s: %s", candidate, response.Errors[0].Message)
		}
		if response.Data.Project == nil {
			continue
		}
		if !strings.EqualFold(response.Data.Project.FullPath, candidate) {
			return "", fmt.Errorf("gitlab project lookup for %s returned unexpected path %q", candidate, response.Data.Project.FullPath)
		}
		return response.Data.Project.FullPath, nil
	}
	return "", fmt.Errorf("project not found or permission denied for registry repository %s", repository)
}
