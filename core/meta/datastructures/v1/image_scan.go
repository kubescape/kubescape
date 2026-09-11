package v1

type ImageScanInfo struct {
	Authority          string
	Username           string
	Password           string
	Token              string
	Images             []string
	Platform           string
	Exceptions         string
	UseDefaultMatchers bool
}
