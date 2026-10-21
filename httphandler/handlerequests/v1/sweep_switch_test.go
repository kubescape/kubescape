package v1

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/httphandler/storage"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
)

// The sweep is opt-in while storage ignores delete preconditions, and a
// single-object scan never sweeps.
func TestShouldSweepOrphanedPostureResults(t *testing.T) {
	singleObject := &cautils.ScanInfo{ScanObject: &objectsenvelopes.ScanObject{}}

	tests := map[string]struct {
		env      string
		set      bool
		scanInfo *cautils.ScanInfo
		want     bool
	}{
		"off by default":               {scanInfo: &cautils.ScanInfo{}},
		"turned off":                   {env: "false", set: true, scanInfo: &cautils.ScanInfo{}},
		"opted in":                     {env: "true", set: true, scanInfo: &cautils.ScanInfo{}, want: true},
		"opted in, single-object scan": {env: "true", set: true, scanInfo: singleObject},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.set {
				t.Setenv(sweepOrphanedPostureResultsEnv, tt.env)
			} else {
				unsetEnvForTest(t, sweepOrphanedPostureResultsEnv)
			}

			assert.Equal(t, tt.want, shouldSweepOrphanedPostureResults(tt.scanInfo))
		})
	}
}

func TestScanCollection(t *testing.T) {
	scanData := &cautils.OPASessionObj{
		ListedGVRs: map[string]bool{"/v1/pods": true, "/v1/secrets": false},
		ScanCoverage: cautils.ScanCoverage{
			FailedGVRPulls:  []cautils.FailedGVRPull{{GVR: "/v1/secrets"}},
			PartialGVRPulls: []cautils.PartialGVRPull{{GVR: "discovery:apps/v1"}},
		},
	}

	assert.Equal(t, storage.Collection{
		Listed:     map[string]bool{"/v1/pods": true, "/v1/secrets": false},
		Incomplete: []string{"/v1/secrets", "discovery:apps/v1"},
	}, scanCollection(scanData))
	assert.Equal(t, storage.Collection{}, scanCollection(nil))
}
