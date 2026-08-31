package core

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSBOMOutput(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		scanType  cautils.ScanTypes
		scanImage bool
		hide      bool
		encrypt   bool
		expectErr string
	}{
		{
			name:     "non-sbom format is unaffected",
			format:   printer.JsonFormat,
			scanType: cautils.ScanTypeCluster,
		},
		{
			name:     "image scan emits an sbom without --scan-images",
			format:   printer.CycloneDXFormat,
			scanType: cautils.ScanTypeImage,
		},
		{
			name:      "posture scan with --scan-images emits an sbom",
			format:    printer.CycloneDXFormat,
			scanType:  cautils.ScanTypeCluster,
			scanImage: true,
		},
		{
			name:      "spdx follows the same rules as cyclonedx",
			format:    printer.SPDXFormat,
			scanType:  cautils.ScanTypeRepo,
			scanImage: true,
		},
		{
			name:      "posture scan without --scan-images is rejected",
			format:    printer.CycloneDXFormat,
			scanType:  cautils.ScanTypeCluster,
			expectErr: "add --scan-images",
		},
		{
			name:      "--hide is rejected because the sbom cannot be anonymized",
			format:    printer.CycloneDXFormat,
			scanType:  cautils.ScanTypeCluster,
			scanImage: true,
			hide:      true,
			expectErr: "not supported with --hide or --encrypt",
		},
		{
			name:      "--encrypt is rejected because the sbom cannot be anonymized",
			format:    printer.SPDXFormat,
			scanType:  cautils.ScanTypeCluster,
			scanImage: true,
			encrypt:   true,
			expectErr: "not supported with --hide or --encrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				ScanImages:        tt.scanImage,
				Hide:              tt.hide,
				EncryptionEnabled: tt.encrypt,
			}
			scanInfo.ScanType = tt.scanType

			err := validateSBOMOutput(scanInfo, tt.format)

			if tt.expectErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}
