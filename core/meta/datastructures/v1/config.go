package v1

import "io"

type SetConfig struct {
	Account        string
	AccessKey      string
	CloudReportURL string
	CloudAPIURL    string
}
type ViewConfig struct {
	Writer       io.Writer
	OutputFormat string
	IncludeEmpty bool
	Key          string
}
type ValidateConfig struct {
	Writer    io.Writer
	Format    string
	Profile   string
	IncludeOK bool
}
type DeleteConfig struct {
}
