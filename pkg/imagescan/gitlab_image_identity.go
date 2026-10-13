package imagescan

import "strings"

// gitLabLocationMatches matches the complete repository identity before its
// version. Tags are mutable: a requested digest must never fall back to a tag
// finding belonging to an earlier build. GitLab can emit registry-qualified
// or repository-only locations, so both are accepted without suffix matching
// arbitrary repository prefixes.
func gitLabLocationMatches(location string, image ContainerImageIdentifier) bool {
	if location == "" || image.Repository == "" || strings.ContainsAny(location, " \t\r\n") {
		return false
	}
	if strings.Contains(location, "://") {
		return false
	}
	repository, digest, hasDigest := strings.Cut(location, "@")
	if hasDigest && (digest == "" || strings.Contains(digest, "@")) {
		return false
	}
	tag := ""
	// A colon in a registry's port is not an image tag.
	if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		tag = repository[colon+1:]
		repository = repository[:colon]
		if tag == "" {
			return false
		}
	}
	if !gitLabRepositoryMatches(repository, image) {
		return false
	}
	if image.Hash != "" {
		return hasDigest && digest == image.Hash
	}
	return image.Tag != "" && tag == image.Tag
}

func gitLabRepositoryMatches(repository string, image ContainerImageIdentifier) bool {
	if repository == image.Repository {
		return true
	}
	if image.Registry != "" {
		return repository == image.Registry+"/"+image.Repository
	}
	// Legacy callers sometimes omit Registry. Only a real registry-shaped
	// first component may be stripped; a subgroup is part of the repository.
	host, path, ok := strings.Cut(repository, "/")
	return ok && path == image.Repository &&
		(strings.ContainsAny(host, ".:") || host == "localhost")
}
