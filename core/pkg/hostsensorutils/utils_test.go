package hostsensorutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/hostsensor"
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
		Resource hostsensor.HostSensorResource
		Err      error
		Expected map[string]apis.StatusInfo
	}{
		{
			Resource: hostsensor.KubeletConfiguration,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/KubeletConfiguration": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			Resource: hostsensor.CNIInfo,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/CNIInfo": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			Resource: hostsensor.HostSensorResource("invalid"),
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
		resource hostsensor.HostSensorResource
		want     string
	}{
		{
			resource: hostsensor.KubeletConfiguration,
			want:     url,
		},
		{
			resource: hostsensor.OsReleaseFile,
			want:     url,
		},
		{
			resource: hostsensor.KubeletCommandLine,
			want:     url,
		},
		{
			resource: hostsensor.KernelVersion,
			want:     url,
		},
		{
			resource: hostsensor.LinuxSecurityHardeningStatus,
			want:     url,
		},
		{
			resource: hostsensor.OpenPortsList,
			want:     url,
		},
		{
			resource: hostsensor.LinuxKernelVariables,
			want:     url,
		},
		{
			resource: hostsensor.KubeletInfo,
			want:     url,
		},
		{
			resource: hostsensor.KubeProxyInfo,
			want:     url,
		},
		{
			resource: hostsensor.ControlPlaneInfo,
			want:     url,
		},
		{
			resource: hostsensor.CloudProviderInfo,
			want:     url,
		},
		{
			resource: hostsensor.CNIInfo,
			want:     url,
		},
		{
			resource: "Fake value",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, hostsensor.MapHostSensorResourceToApiGroup(tt.resource))
		})
	}
}
