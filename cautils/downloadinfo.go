package cautils

import (
	"os"
	"path/filepath"

	"github.com/armosec/kubescape/cautils/getter"
)

type DownloadInfo struct {
	Path          string
	FrameworkName string
}

func GetDefaultPath(frameworkName string) string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, getter.DefaultLocalStore, frameworkName+".json")
	}
	return filepath.Join(getter.DefaultLocalStore, frameworkName+".json")
}
