// Package clustercomponents builds a version inventory of the components a
// cluster runs on, recording anything it cannot establish as a gap.
package clustercomponents

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	k8shostsensor "github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/version"
)

type Inventory struct {
	APIServer *ComponentVersion `json:"apiServer,omitempty"`
	Nodes     []Node            `json:"nodes"`
	Gaps      []Gap             `json:"gaps,omitempty"`
}

type Node struct {
	Name            string            `json:"name"`
	OperatingSystem string            `json:"operatingSystem"`
	Architecture    string            `json:"architecture"`
	Kubelet         *ComponentVersion `json:"kubelet,omitempty"`
	Runtime         *ComponentVersion `json:"runtime,omitempty"`
	Kernel          KernelEvidence    `json:"kernel"`
}

// ProcVersion and the OS release fields are only set when the node-agent
// reported them.
type KernelEvidence struct {
	Release     string `json:"release"`
	OSImage     string `json:"osImage"`
	ProcVersion string `json:"procVersion,omitempty"`
	OSID        string `json:"osID,omitempty"`
	OSVersionID string `json:"osVersionID,omitempty"`
}

type Gap struct {
	Component Component `json:"component"`
	Node      string    `json:"node,omitempty"`
	Reason    string    `json:"reason"`
}

// Build assembles the inventory. apiServer and hostData may be nil.
func Build(apiServer *version.Info, nodes []corev1.Node, hostData []hostsensor.HostSensorDataEnvelope) Inventory {
	var inv Inventory

	if apiServer == nil || apiServer.GitVersion == "" {
		inv.Gaps = append(inv.Gaps, Gap{Component: APIServer, Reason: "API server version not available"})
	} else if v, err := ParseKubernetesVersion(APIServer, apiServer.GitVersion); err != nil {
		inv.Gaps = append(inv.Gaps, Gap{Component: APIServer, Reason: err.Error()})
	} else {
		inv.APIServer = &v
	}

	procVersions, osReleases := indexHostData(hostData)

	inv.Nodes = make([]Node, 0, len(nodes))
	for i := range nodes {
		info := nodes[i].Status.NodeInfo
		n := Node{
			Name:            nodes[i].Name,
			OperatingSystem: info.OperatingSystem,
			Architecture:    info.Architecture,
			Kernel: KernelEvidence{
				Release:     info.KernelVersion,
				OSImage:     info.OSImage,
				ProcVersion: procVersions[nodes[i].Name],
			},
		}
		if osRelease, ok := osReleases[nodes[i].Name]; ok {
			n.Kernel.OSID = osRelease["ID"]
			n.Kernel.OSVersionID = osRelease["VERSION_ID"]
		}

		if info.KubeletVersion == "" {
			inv.Gaps = append(inv.Gaps, Gap{Component: Kubelet, Node: n.Name, Reason: "kubelet version not reported"})
		} else if v, err := ParseKubernetesVersion(Kubelet, info.KubeletVersion); err != nil {
			inv.Gaps = append(inv.Gaps, Gap{Component: Kubelet, Node: n.Name, Reason: err.Error()})
		} else {
			n.Kubelet = &v
		}

		if info.ContainerRuntimeVersion == "" {
			inv.Gaps = append(inv.Gaps, Gap{Component: ContainerRuntime, Node: n.Name, Reason: "container runtime version not reported"})
		} else if v, err := ParseContainerRuntimeVersion(info.ContainerRuntimeVersion); err != nil {
			inv.Gaps = append(inv.Gaps, Gap{Component: ContainerRuntime, Node: n.Name, Reason: err.Error()})
		} else {
			n.Runtime = &v
		}

		inv.Nodes = append(inv.Nodes, n)
	}

	slices.SortFunc(inv.Nodes, func(a, b Node) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortStableFunc(inv.Gaps, func(a, b Gap) int {
		return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.Component, b.Component))
	})
	return inv
}

func indexHostData(envelopes []hostsensor.HostSensorDataEnvelope) (procVersions map[string]string, osReleases map[string]map[string]string) {
	procVersions = map[string]string{}
	osReleases = map[string]map[string]string{}
	for i := range envelopes {
		e := &envelopes[i]
		switch e.GetKind() {
		case k8shostsensor.KernelVersion.String():
			if content, ok := hostDataContent(e.Data); ok {
				procVersions[e.GetName()] = strings.TrimSpace(content)
			}
		case k8shostsensor.OsReleaseFile.String():
			if content, ok := hostDataContent(e.Data); ok {
				osReleases[e.GetName()] = parseOSRelease(content)
			}
		}
	}
	return procVersions, osReleases
}

func hostDataContent(data json.RawMessage) (string, bool) {
	var spec struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(data, &spec); err != nil || spec.Content == "" {
		return "", false
	}
	return spec.Content, true
}

// See os-release(5).
func parseOSRelease(content string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		fields[key] = value
	}
	return fields
}
