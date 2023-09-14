package cautils

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-k8s-go/wlid"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
)

type OperatorSubCommand string

const (
	ScanCommand                OperatorSubCommand = "scan"
	ScanConfigCommand          OperatorSubCommand = "config"
	ScanVulnerabilitiesCommand OperatorSubCommand = "vulnerabilities"
	KubescapeScanV1            string             = "scanV1"
)

type VulnerabilitiesScanInfo struct {
	IncludeNamespaces []string
	ClusterName       string
}

type ConfigScanInfo struct {
	Submit             bool
	ExcludedNamespaces []string
	IncludedNamespaces []string
	HostScanner        bool
	Frameworks         []string // Load frameworks for config scan
}

type OperatorInfo struct {
	Subcommands []OperatorSubCommand
	OperatorScanInfo
}

type OperatorConnector interface {
	StartPortForwarder() error
	StopPortForwarder()
	GetPortForwardLocalhost() string
}

type OperatorScanInfo interface {
	GetRequestPayload() *apis.Commands
}

func (v *VulnerabilitiesScanInfo) GetRequestPayload() *apis.Commands {
	var commands []apis.Command

	clusterName := v.ClusterName
	if len(v.IncludeNamespaces) == 0 {
		wildWlid := wlid.GetWLID(clusterName, "", "", "")
		command := apis.Command{
			CommandName: apis.TypeScanImages,
			WildWlid:    wildWlid,
		}
		commands = append(commands, command)
	} else {
		for i := range v.IncludeNamespaces {
			wildWlid := wlid.GetWLID(clusterName, v.IncludeNamespaces[i], "", "")
			command := apis.Command{
				CommandName: apis.TypeScanImages,
				WildWlid:    wildWlid,
			}
			commands = append(commands, command)
		}
	}

	return &apis.Commands{
		Commands: commands,
	}
}

func (c *ConfigScanInfo) GetRequestPayload() *apis.Commands {
	return &apis.Commands{
		Commands: []apis.Command{
			{
				CommandName: apis.TypeRunKubescape,
				Args: map[string]interface{}{
					KubescapeScanV1: utilsmetav1.PostScanRequest{
						Submit:             &c.Submit,
						ExcludedNamespaces: c.ExcludedNamespaces,
						IncludeNamespaces:  c.IncludedNamespaces,
						TargetType:         apisv1.KindFramework,
						TargetNames:        c.Frameworks,
						HostScanner:        &c.HostScanner,
					},
				},
			},
		},
	}
}
