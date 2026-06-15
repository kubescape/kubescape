package hostsensorutils

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeHostSensorDiscovery returns a discovery.DiscoveryInterface whose
// ServerPreferredResources reports the host-sensor CRDs as the cluster would.
// This lets IsKindKubernetes/ResourceGroupToString normalize host-sensor
// kinds the same way they do against a real cluster.
type fakeHostSensorDiscovery struct {
	*fakediscovery.FakeDiscovery
}

func (f *fakeHostSensorDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return []*metav1.APIResourceList{
		{
			GroupVersion: "hostdata.kubescape.cloud/v1beta0",
			APIResources: []metav1.APIResource{
				{Name: "kubeletinfos", Kind: "KubeletInfo", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}},
				{Name: "cniinfos", Kind: "CNIInfo", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}},
			},
		},
	}, nil
}

func TestMain(m *testing.M) {
	// Register host-sensor CRDs into k8sinterface's global discovery mapping
	// so that ResourceGroupToString normalizes "KubeletInfo"/"CNIInfo" to their
	// plural lowercase CRD names ("kubeletinfos"/"cniinfos"), matching what
	// happens against a real cluster where these CRDs are installed.
	k8sinterface.InitializeMapResources(&fakeHostSensorDiscovery{
		FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &k8stesting.Fake{}},
	})
	os.Exit(m.Run())
}

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
			// KubeletConfiguration is not a registered CRD kind, so
			// ResourceGroupToString falls back to the raw group/version/kind triplet.
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
			// CNIInfo is registered as the "cniinfos" CRD (see TestMain), so
			// ResourceGroupToString normalizes the key to its plural lowercase form.
			Resource: hostsensor.CNIInfo,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/cniinfos": {
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   testErr.Error(),
				},
			},
		},
		{
			// KubeletInfo is registered as the "kubeletinfos" CRD (see TestMain), so
			// ResourceGroupToString normalizes the key to its plural lowercase form.
			Resource: hostsensor.KubeletInfo,
			Err:      testErr,
			Expected: map[string]apis.StatusInfo{
				"hostdata.kubescape.cloud/v1beta0/kubeletinfos": {
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
			result := make(map[string]apis.StatusInfo, 1)
			addInfoToMap(tc.Resource, result, tc.Err)

			require.EqualValues(t, tc.Expected, result)
		})
	}
}

// TestAddInfoToMap_BuildScanCoverageRecognizesHostSensorFailure is a regression
// test for the bug where addInfoToMap used JoinResourceTriplets while
// collectHostResources used ResourceGroupToString, producing different keys
// for the same CRD ("KubeletInfo" vs "kubeletinfos"). BuildScanCoverage only
// surfaces an InfoMap entry as a FailedGVRPull/NotEvaluatedControl when its
// key matches ResourceToControlsMap, so the mismatch silently dropped
// host-sensor pull failures from scan coverage.
func TestAddInfoToMap_BuildScanCoverageRecognizesHostSensorFailure(t *testing.T) {
	testErr := errors.New("failed to list CRDs")

	infoMap := make(map[string]apis.StatusInfo)
	addInfoToMap(hostsensor.KubeletInfo, infoMap, testErr)

	const expectedKey = "hostdata.kubescape.cloud/v1beta0/kubeletinfos"
	resourceToControlsMap := map[string][]string{
		expectedKey: {"C-0001"},
	}

	coverage := cautils.BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)

	require.Len(t, coverage.FailedGVRPulls, 1)
	assert.Equal(t, expectedKey, coverage.FailedGVRPulls[0].GVR)
	assert.Equal(t, testErr.Error(), coverage.FailedGVRPulls[0].Error)

	require.Len(t, coverage.NotEvaluatedControls, 1)
	assert.Equal(t, "C-0001", coverage.NotEvaluatedControls[0].ControlID)
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
