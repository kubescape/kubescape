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

	parts := strings.Split(value, "/")
	platform, err := image.NewPlatform(value)
	if err != nil {
		return "", fmt.Errorf("invalid image platform %q: %w", value, err)
	}
	if len(parts) >= 2 {
		firstComponent, firstErr := image.NewPlatform(parts[0])
		switch {
		case firstErr != nil:
			return "", fmt.Errorf("invalid image platform %q: unknown operating system %q", value, parts[0])
		case len(parts) >= 3 && firstComponent.Architecture != "":
			return "", fmt.Errorf("invalid image platform %q: an operating system is required before architecture and variant", value)
		case firstComponent.OS != "" && !strings.EqualFold(firstComponent.OS, platform.OS):
			return "", fmt.Errorf("invalid image platform %q: operating system %q was not preserved by the platform parser", value, parts[0])
		}
	}
	if platform.OS == "" || platform.Architecture == "" {
		return "", fmt.Errorf("invalid image platform %q: both operating system and architecture are required", value)
	}

	return platform.String(), nil
}
