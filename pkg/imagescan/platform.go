package imagescan

import (
	"fmt"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
)

// ScanOptions controls how an image source is resolved before its packages are
// matched against the vulnerability database. An empty Platform preserves the
// provider's default behavior for callers that do not have target-platform
// information.
type ScanOptions struct {
	Platform string
}

// NormalizePlatform validates an OCI platform and returns the canonical
// os/architecture[/variant] spelling understood by Syft and Stereoscope.
// Architecture-only values such as "amd64" are accepted and normalized to
// "linux/amd64", matching container tooling conventions.
func NormalizePlatform(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	platform, err := image.NewPlatform(value)
	if err != nil {
		return "", fmt.Errorf("invalid image platform %q: %w", value, err)
	}
	if platform.OS == "" || platform.Architecture == "" {
		return "", fmt.Errorf("invalid image platform %q: both operating system and architecture are required", value)
	}

	return platform.String(), nil
}
