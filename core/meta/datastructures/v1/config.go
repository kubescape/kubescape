package v1

import "io"

type SetConfig struct {
	Account        string
	CloudReportURL string
	CloudAPIURL    string
}

type ViewConfig struct {
	Writer io.Writer
}

type DeleteConfig struct {
}
