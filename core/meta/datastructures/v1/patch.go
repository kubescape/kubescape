package v1

import (
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

type PatchInfo struct {
	Image           string        // image to be patched
	PatchedImageTag string        // can be empty, if empty then the image tag will be patched with the latest tag
	BuildkitAddress string        // buildkit address
	Timeout         time.Duration // timeout for patching an image
	IgnoreError     bool          // ignore errors and continue patching
	BuildKitOpts    buildkit.Opts //build kit options

	// Image registry credentials
	Username string // username for registry login
	Password string // password for registry login

	// registry.com/namespace/<image-name>:<image-tag>
	ImageName string // image name
	ImageTag  string // image tag
}
