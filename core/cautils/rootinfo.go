package cautils

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type RootInfo struct {
	Logger             string // logger level
	LoggerName         string // logger name ("pretty"/"zap"/"none")
	CacheDir           string // cached dir
	DisableColor       bool   // Disable Color
	EnableColor        bool   // Force enable Color
	DiscoveryServerURL string // Discovery Server URL  (See https://github.com/kubescape/backend/tree/main/pkg/servicediscovery)
	KubeContext        string //  context name
}
type CloudURLs struct {
	CloudReportURL string
	CloudAPIURL    string
}

// To check if the provided account ID is valid
func ValidateAccountID(accountID string) error {

	if strings.TrimSpace(accountID) == "" {
		return fmt.Errorf("no arguements provided")
	}

	// Check if the Account-ID is valid
	if _, err := uuid.Parse(accountID); accountID != "" && err != nil {
		return fmt.Errorf("bad argument: accound ID must be a valid UUID")
	}

	return nil
}
