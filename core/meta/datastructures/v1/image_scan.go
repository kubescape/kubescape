package v1

type ImageScanInfo struct {
	Authority          string
	Username           string
	Password           string
	Token              string
	Image              string
	Exceptions         string
	UseDefaultMatchers bool
}
