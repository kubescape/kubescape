package getter

import (
	"path/filepath"
)

var mockFrameworkBasePath = filepath.Join("examples", "mocks", "frameworks")

func MockNewLoadPolicy() *LoadPolicy {
	return &LoadPolicy{
		filePaths: []string{""},
	}
}
