package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddImageScanTarget_KeepsExistingWhenNewSkipsUnavailable(t *testing.T) {
	seen := make(map[imageScanTargetKey]ImageScanTarget)
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/amd64"})
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/amd64", SkipUnavailable: true})

	require.Len(t, seen, 1)
	for _, got := range seen {
		assert.False(t, got.SkipUnavailable, "fail-closed existing target must be kept")
	}
}

func TestAddImageScanTarget_ReplacesSkipUnavailableWithExplicitTarget(t *testing.T) {
	seen := make(map[imageScanTargetKey]ImageScanTarget)
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/amd64", SkipUnavailable: true})
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/amd64"})

	require.Len(t, seen, 1)
	for _, got := range seen {
		assert.False(t, got.SkipUnavailable, "explicit target must replace the inferred fan-out target")
	}
}

func TestAddImageScanTarget_KeepsDifferentPlatforms(t *testing.T) {
	seen := make(map[imageScanTargetKey]ImageScanTarget)
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/amd64"})
	addImageScanTarget(seen, ImageScanTarget{Image: "nginx:1.25", Platform: "linux/arm64"})

	assert.Len(t, seen, 2)
}
