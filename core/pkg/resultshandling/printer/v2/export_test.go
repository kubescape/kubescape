package printer

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

// BuildSeverityExceptionImageScanDataForTest exports buildSeverityExceptionImageScanData
// for external test packages in this directory.
func BuildSeverityExceptionImageScanDataForTest() cautils.ImageScanData {
	return buildSeverityExceptionImageScanData()
}

// ConfigurationOutputFixtureForTest exports configurationOutputFixture for external test packages.
func ConfigurationOutputFixtureForTest(t testing.TB, size int) *cautils.OPASessionObj {
	return configurationOutputFixture(t, size)
}
