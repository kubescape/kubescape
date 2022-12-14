package v1

import "github.com/kubescape/kubescape/v2/core/cautils"

type DownloadInfo struct {
	Path        string // directory to save artifact. Default is "~/.kubescape/"
	FileName    string // can be empty
	Target      string // type of artifact to download
	Name        string // name of artifact to download
	ID          string // ID of artifact to download (relevant only for controls)
	Credentials cautils.Credentials
}
