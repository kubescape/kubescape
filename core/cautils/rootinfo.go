package cautils

type RootInfo struct {
	Logger       string // logger level
	LoggerName   string // logger name ("pretty"/"zap"/"none")
	CacheDir     string // cached dir
	DisableColor bool   // Disable Color
	EnableColor  bool   // Force enable Color

	KSCloudBEURLs    string // Kubescape Cloud URL
	KSCloudBEURLsDep string // Kubescape Cloud URL
}

type Credentials struct {
	Account   string
	ClientID  string
	SecretKey string
}
