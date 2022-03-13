package v1

type DownloadInfo struct {
	Path     string // directory to save artifact. Default is "~/.kubescape/"
	FileName string // can be empty
	Target   string // type of artifact to download
	Name     string // name of artifact to download
	Account  string // AccountID
}
