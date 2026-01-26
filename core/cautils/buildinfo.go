package cautils

import (
	"os"
	"runtime/debug"

	"github.com/kubescape/backend/pkg/versioncheck"
)

var Client string

func init() {
	// Try to get version from build info (Go 1.24+ automatically populates this from VCS tags)
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		versioncheck.BuildNumber = info.Main.Version
	}

	// Fallback to RELEASE environment variable
	if versioncheck.BuildNumber == "" {
		versioncheck.BuildNumber = os.Getenv("RELEASE")
	}

	// Client is typically set via ldflags: -X "github.com/kubescape/kubescape/v3/core/cautils.Client=..."
	if Client != "" {
		versioncheck.Client = Client
	}
}
