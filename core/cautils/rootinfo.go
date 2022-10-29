package cautils

import (
	"fmt"

	"github.com/google/uuid"
)

type RootInfo struct {
	Logger       string // logger level
	LoggerName   string // logger name ("pretty"/"zap"/"none")
	CacheDir     string // cached dir
	DisableColor bool   // Disable Color
	EnableColor  bool   // Force enable Color

	KSCloudBEURLs    string // Kubescape Cloud URL
	KSCloudBEURLsDep string // Kubescape Cloud URL
}
type CloudURLs struct {
	CloudReportURL string
	CloudAPIURL    string
	CloudUIURL     string
	CloudAuthURL   string
}

type Credentials struct {
	Account   string
	ClientID  string
	SecretKey string
}

// To check if the user's credentials: accountID / clientID / secretKey are valid.
func (credentials *Credentials) Validate() error {

	// Check if the Account-ID is valid
	if _, err := uuid.Parse(credentials.Account); credentials.Account != "" && err != nil {
		return fmt.Errorf("bad argument: account must be a valid UUID")
	}
	// Check if the Client-ID is valid
	if _, err := uuid.Parse(credentials.ClientID); credentials.ClientID != "" && err != nil {
		return fmt.Errorf("bad argument: account must be a valid UUID")
	}

	// Check if the Secret-Key is valid
	if _, err := uuid.Parse(credentials.SecretKey); credentials.SecretKey != "" && err != nil {
		return fmt.Errorf("bad argument: account must be a valid UUID")
	}

	return nil
}
