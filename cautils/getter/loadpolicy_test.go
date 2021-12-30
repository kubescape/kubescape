package getter

import (
	"os"
	"path/filepath"
	"testing"
)

var mockFrameworkBasePath = filepath.Join("examples", "mocks", "frameworks")

func MockNewLoadPolicy() *LoadPolicy {
	return &LoadPolicy{
		filePaths: []string{""},
	}
}

func TestBla(t *testing.T) {
	dir, _ := os.Getwd()
	t.Error(dir)
}
