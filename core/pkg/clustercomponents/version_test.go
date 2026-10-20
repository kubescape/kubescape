package clustercomponents

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKubernetesVersion(t *testing.T) {
	tests := []struct {
		raw        string
		version    string
		assessment Assessment
		wantErr    bool
	}{
		{raw: "v1.29.2", version: "1.29.2", assessment: Verified},
		{raw: "v1.29.4", version: "1.29.4", assessment: Verified},
		{raw: "1.30.1", version: "1.30.1", assessment: Verified},
		{raw: "v1.30.2+k3s1", version: "1.30.2", assessment: Verified},
		{raw: "v1.30.2+rke2r1", version: "1.30.2", assessment: Verified},
		{raw: "v1.29.3-eks-adc7111", version: "1.29.3", assessment: VendorBuild},
		{raw: "v1.28.9-gke.1000", version: "1.28.9", assessment: VendorBuild},
		{raw: "v1.27.10+28ed2d7", version: "1.27.10", assessment: VendorBuild},
		{raw: "v1.31.0-rc.1", wantErr: true},
		{raw: "v1.31.0-alpha.3", wantErr: true},
		{raw: "v1.29.3-custom", wantErr: true},
		{raw: "v1.29", wantErr: true},
		{raw: "v1.29.3.1", wantErr: true},
		{raw: "latest", wantErr: true},
		{raw: "v1.29.3+", wantErr: true},
		{raw: "v1.29.3-dev", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseKubernetesVersion(Kubelet, tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ComponentVersion{Component: Kubelet, Version: tt.version, RawVersion: tt.raw, Assessment: tt.assessment}, got)
		})
	}
}

func TestParseContainerRuntimeVersion(t *testing.T) {
	tests := []struct {
		raw        string
		component  Component
		version    string
		assessment Assessment
		wantErr    bool
	}{
		{raw: "containerd://1.7.11", component: Containerd, version: "1.7.11", assessment: Verified},
		{raw: "containerd://2.0.0", component: Containerd, version: "2.0.0", assessment: Verified},
		{raw: "containerd://v1.7.11", component: Containerd, version: "1.7.11", assessment: Verified},
		{raw: "cri-o://1.29.1", component: CRIO, version: "1.29.1", assessment: Verified},
		{raw: "containerd://1.7.15-k3s1", component: Containerd, version: "1.7.15", assessment: VendorBuild},
		{raw: "containerd://1.6.28+bottlerocket", component: Containerd, version: "1.6.28", assessment: VendorBuild},
		{raw: "containerd://1.7.22-1", component: Containerd, version: "1.7.22", assessment: VendorBuild},
		{raw: "containerd://1.7.11-1.amzn2.0.1", component: Containerd, version: "1.7.11", assessment: VendorBuild},
		{raw: "cri-o://1.29.6-3.rhaos4.16.git0e72a5b.el9", component: CRIO, version: "1.29.6", assessment: VendorBuild},
		{raw: "containerd://2.0.0-rc.3", wantErr: true},
		{raw: "containerd://1.7.0-rc1", wantErr: true},
		{raw: "docker://24.0.7", wantErr: true},
		{raw: "containerd://", wantErr: true},
		{raw: "1.7.11", wantErr: true},
		{raw: "containerd://2.0.0-dev", wantErr: true},
		{raw: "containerd://2.0.0-pre.1", wantErr: true},
		{raw: "containerd://1.7.11+", wantErr: true},
		{raw: "containerd://1.7.11-", wantErr: true},
		{raw: "containerd://1.7.11-custom", wantErr: true},
		{raw: "containerd://1.7.11+dirty", wantErr: true},
		{raw: "cri-o://1.29.6-3.el9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseContainerRuntimeVersion(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ComponentVersion{Component: tt.component, Version: tt.version, RawVersion: tt.raw, Assessment: tt.assessment}, got)
		})
	}
}
