package v1

import "io"

type SetConfig struct {
	Account        string
	ClientID       string
	SecretKey      string
	CloudReportURL string
	CloudAPIURL    string
	CloudUIURL     string
	CloudAuthURL   string
}

type ViewConfig struct {
	Writer io.Writer
}

type DeleteConfig struct {
}
