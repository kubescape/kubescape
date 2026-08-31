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

	ErrImageScanAnonymization = errors.New("--hide and --encrypt are not supported for image scans: an image report is the Anchore scan document and its SBOM, whose package identity and relationships are keyed by content-derived IDs that anonymization cannot rewrite. To get anonymized image findings, run a posture scan with --scan-images, where image references are anonymized and no SBOM is emitted")
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

// ValidateImageScanAnonymization rejects --hide/--encrypt on a standalone
// image scan.
//
// Both flags are registered on the parent scan command, so `scan image`
// inherits them, but the anonymizer only ever runs over a posture session
// (core/core/scan.go calls it from ScanContext, and nothing calls it from the
// image path). On this path the flags were accepted and silently did nothing
// while the image reference, its SBOM and the package file inventory were
// written out in full.
//
// It is deliberately not called from ValidateImageScanInfo: the combined
// `scan framework --scan-images` path shares that validator and does support
// both flags, since it anonymizes image references and never emits the SBOM.
func ValidateImageScanAnonymization(scanInfo *cautils.ScanInfo) error {
	if scanInfo == nil {
		return nil
	}
	if scanInfo.Hide || scanInfo.EncryptionEnabled {
		return ErrImageScanAnonymization
	}
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
