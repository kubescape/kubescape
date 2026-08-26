package shared

import (
	"errors"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
)

var (
	ErrRegistryUsernamePassword = errors.New("registry username and password must be provided together")
	ErrRegistryAuthConflict     = errors.New("registry token cannot be used together with registry username/password")
	ErrRegistryAuthorityNoAuth  = errors.New("registry authority requires registry credentials")
	ErrRegistryAuthorityMissing = errors.New("registry credentials for --scan-images require registry authority")
)

type ImageCredentials struct {
	Authority string
	Username  string
	Password  string
	Token     string
}

// ValidateImageScanInfo validates the ScanInfo struct for image scanning commands
func ValidateImageScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if err := ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}
	if err := ValidateThresholds(scanInfo); err != nil {
		return err
	}
	platform, err := imagescan.NormalizePlatform(scanInfo.ImagePlatform)
	if err != nil {
		return err
	}
	scanInfo.ImagePlatform = platform
	return nil
}

func ValidateImageCredentials(credentials ImageCredentials) error {
	return ValidateRegistryCredentials(credentials.Username, credentials.Password, credentials.Token, credentials.Authority)
}

func ValidateWorkloadImageCredentials(credentials ImageCredentials) error {
	if err := ValidateImageCredentials(credentials); err != nil {
		return err
	}
	if credentials.Authority == "" && hasRegistryAuthenticator(credentials.Username, credentials.Password, credentials.Token) {
		return ErrRegistryAuthorityMissing
	}
	return nil
}

func ValidateRegistryCredentials(username, password, token, authority string) error {
	hasUsernamePassword := username != "" || password != ""
	hasCompleteUsernamePassword := username != "" && password != ""
	hasToken := token != ""

	if hasUsernamePassword && !hasCompleteUsernamePassword {
		if hasToken {
			return ErrRegistryAuthConflict
		}
		return ErrRegistryUsernamePassword
	}
	if hasCompleteUsernamePassword && hasToken {
		return ErrRegistryAuthConflict
	}
	if authority != "" && !hasCompleteUsernamePassword && !hasToken {
		return ErrRegistryAuthorityNoAuth
	}

	return nil
}

func hasRegistryAuthenticator(username, password, token string) bool {
	return token != "" || (username != "" && password != "")
}
