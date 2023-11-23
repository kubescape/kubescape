package hostsensorutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddInfoToMap(t *testing.T) {
	t.Parallel()

	// NOTE: the function being tested is hard to test, because
	// the worker pool mutes most errors.
	//
	// Essentially, unless we hit some extreme edge case, we never get an error to be added to the map.
	testErr := errors.New("test error")

	for _, toPin := range []struct {
		Resource scannerResource
		Err      error
		Expected map[string]apis.StatusInfo
	}{
		{
			Resource: KubeletConfiguration,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/KubeletConfiguration": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			Resource: CNIInfo,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/CNIInfo": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			Resource: scannerResource("invalid"),
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"//invalid": { // no group, no version
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
	} {
		tc := toPin

		t.Run(fmt.Sprintf("should expect a status for resource %s", tc.Resource), func(t *testing.T) {
			t.Parallel()

			result := make(map[string]apis.StatusInfo, 1)
			addInfoToMap(tc.Resource, result, tc.Err)

			require.EqualValues(t, tc.Expected, result)
		})
	}
}

func TestMapHostSensorResourceToApiGroup(t *testing.T) {
	url := "hostdata.kubescape.cloud/v1beta0"

	tests := []struct {
		resource scannerResource
		want     string
	}{
		{
			resource: KubeletConfiguration,
			want:     url,
		},
		{
			resource: OsReleaseFile,
			want:     url,
		},
		{
			resource: KubeletCommandLine,
			want:     url,
		},
		{
			resource: KernelVersion,
			want:     url,
		},
		{
			resource: LinuxSecurityHardeningStatus,
			want:     url,
		},
		{
			resource: OpenPortsList,
			want:     url,
		},
		{
			resource: LinuxKernelVariables,
			want:     url,
		},
		{
			resource: KubeletInfo,
			want:     url,
		},
		{
			resource: KubeProxyInfo,
			want:     url,
		},
		{
			resource: ControlPlaneInfo,
			want:     url,
		},
		{
			resource: CloudProviderInfo,
			want:     url,
		},
		{
			resource: CNIInfo,
			want:     url,
		},
		{
			resource: "Fake value",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, mapHostSensorResourceToApiGroup(tt.resource))
		})
	}
}
