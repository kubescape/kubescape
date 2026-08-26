package v1

type ImageScanInfo struct {
	Authority          string
	Username           string
	Password           string
	Token              string
	Image              string
	Platform           string
	Exceptions         string
	UseDefaultMatchers bool
}
