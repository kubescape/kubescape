package v1

type DownloadInfo struct {
	Path       string // directory to save artifact. Default is "~/.kubescape/"
	FileName   string // can be empty
	Target     string // type of artifact to download
	Identifier string // identifier of artifact to download
	AccountID  string
	AccessKey  string
}
