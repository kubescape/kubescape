package clustercomponents

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
)

func node(name string, info corev1.NodeSystemInfo) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{NodeInfo: info},
	}
}

func hostData(t *testing.T, kind, nodeName string, data any) hostsensor.HostSensorDataEnvelope {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	e := hostsensor.HostSensorDataEnvelope{Kind: kind, Data: raw}
	e.SetName(nodeName)
	return e
}

func TestBuild(t *testing.T) {
	nodes := []corev1.Node{
		node("ubuntu-1", corev1.NodeSystemInfo{
			KubeletVersion:          "v1.28.4",
			ContainerRuntimeVersion: "containerd://1.7.11",
			KernelVersion:           "5.15.0-1057-aws",
			OSImage:                 "Ubuntu 22.04.4 LTS",
			OperatingSystem:         "linux",
			Architecture:            "amd64",
		}),
		node("al2-1", corev1.NodeSystemInfo{
			KubeletVersion:          "v1.28.4-eks-adc7111",
			ContainerRuntimeVersion: "containerd://1.7.11-1.amzn2.0.1",
			KernelVersion:           "5.10.205-195.807.amzn2.x86_64",
			OSImage:                 "Amazon Linux 2",
			OperatingSystem:         "linux",
			Architecture:            "amd64",
		}),
	}
	data := []hostsensor.HostSensorDataEnvelope{
		hostData(t, "KernelVersion", "ubuntu-1", map[string]string{
			"content": "Linux version 5.15.0-1057-aws (buildd@lcy02-amd64-033) #63-Ubuntu SMP Mon Mar 25 10:27:19 UTC 2024\n",
		}),
		hostData(t, "OsReleaseFile", "ubuntu-1", map[string]string{
			"content": "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n# comment\nID=ubuntu\nID_LIKE=debian\n",
		}),
		hostData(t, "KernelVersion", "unknown-node", map[string]string{"content": "Linux version 6.1.0"}),
		hostData(t, "LinuxKernelVariables", "ubuntu-1", map[string]string{"content": "ignored"}),
	}

	inv := Build(&version.Info{GitVersion: "v1.28.4-eks-adc7111"}, nodes, data)

	assert.Equal(t, &ComponentVersion{Component: APIServer, Version: "1.28.4", RawVersion: "v1.28.4-eks-adc7111", Assessment: VendorBuild}, inv.APIServer)
	assert.Empty(t, inv.Gaps)
	require.Len(t, inv.Nodes, 2)

	al2, ubuntu := inv.Nodes[0], inv.Nodes[1]
	assert.Equal(t, "al2-1", al2.Name)
	assert.Equal(t, VendorBuild, al2.Kubelet.Assessment)
	assert.Equal(t, &ComponentVersion{Component: Containerd, Version: "1.7.11", RawVersion: "containerd://1.7.11-1.amzn2.0.1", Assessment: VendorBuild}, al2.Runtime)
	assert.Equal(t, KernelEvidence{Release: "5.10.205-195.807.amzn2.x86_64", OSImage: "Amazon Linux 2"}, al2.Kernel)

	assert.Equal(t, Node{
		Name:            "ubuntu-1",
		OperatingSystem: "linux",
		Architecture:    "amd64",
		Kubelet:         &ComponentVersion{Component: Kubelet, Version: "1.28.4", RawVersion: "v1.28.4", Assessment: Verified},
		Runtime:         &ComponentVersion{Component: Containerd, Version: "1.7.11", RawVersion: "containerd://1.7.11", Assessment: Verified},
		Kernel: KernelEvidence{
			Release:     "5.15.0-1057-aws",
			OSImage:     "Ubuntu 22.04.4 LTS",
			ProcVersion: "Linux version 5.15.0-1057-aws (buildd@lcy02-amd64-033) #63-Ubuntu SMP Mon Mar 25 10:27:19 UTC 2024",
			OSID:        "ubuntu",
			OSVersionID: "22.04",
		},
	}, ubuntu)
}

func TestBuildRecordsGaps(t *testing.T) {
	nodes := []corev1.Node{
		node("win-1", corev1.NodeSystemInfo{
			KubeletVersion:          "v1.31.0-rc.1",
			ContainerRuntimeVersion: "docker://24.0.7",
			OperatingSystem:         "windows",
		}),
		node("bare-1", corev1.NodeSystemInfo{}),
	}

	for _, apiServer := range []*version.Info{nil, {}} {
		inv := Build(apiServer, nodes, nil)

		assert.Nil(t, inv.APIServer)
		require.Len(t, inv.Nodes, 2)
		for _, n := range inv.Nodes {
			assert.Nil(t, n.Kubelet)
			assert.Nil(t, n.Runtime)
		}

		got := make([][2]string, 0, len(inv.Gaps))
		for _, g := range inv.Gaps {
			assert.NotEmpty(t, g.Reason)
			got = append(got, [2]string{g.Node, string(g.Component)})
		}
		assert.Equal(t, [][2]string{
			{"", "kube-apiserver"},
			{"bare-1", "container-runtime"},
			{"bare-1", "kubelet"},
			{"win-1", "container-runtime"},
			{"win-1", "kubelet"},
		}, got)
	}

	inv := Build(&version.Info{GitVersion: "v1.29.3-custom"}, nil, nil)
	assert.Equal(t, []Gap{{Component: APIServer, Reason: `unrecognized version suffix in "v1.29.3-custom"`}}, inv.Gaps)
	assert.NotNil(t, inv.Nodes)
}

func TestHostDataContent(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
		ok   bool
	}{
		{name: "content", data: `{"content":"Linux version 6.1.0"}`, want: "Linux version 6.1.0", ok: true},
		{name: "bare string", data: `"Linux version 6.1.0"`},
		{name: "empty content", data: `{"content":""}`},
		{name: "unexpected shape", data: `{"version":"5.15.0"}`},
		{name: "invalid json", data: `{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := hostDataContent(json.RawMessage(tt.data))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease("NAME=\"Amazon Linux\"\nVERSION_ID='2'\nID=amzn\n\nBROKEN LINE\nEMPTY=\nQUOTE=\"\n")
	assert.Equal(t, map[string]string{
		"NAME":       "Amazon Linux",
		"VERSION_ID": "2",
		"ID":         "amzn",
		"EMPTY":      "",
		"QUOTE":      `"`,
	}, got)
}
