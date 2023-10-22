package shared

import "github.com/kubescape/kubescape/v3/core/cautils"

type ImageCredentials struct {
	Username string
	Password string
}

// ValidateImageScanInfo validates the ScanInfo struct for image scanning commands
func ValidateImageScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if err := ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}
	return nil
}
