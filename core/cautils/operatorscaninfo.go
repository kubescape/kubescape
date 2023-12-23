package cautils

import (
	"errors"

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
	ClusterName       string
	IncludeNamespaces []string
}

type ConfigScanInfo struct {
	ExcludedNamespaces []string
	IncludedNamespaces []string
	Frameworks         []string
	HostScanner        bool
}

type OperatorInfo struct {
	Namespace string
	OperatorScanInfo
	Subcommands []OperatorSubCommand
}

type OperatorConnector interface {
	StartPortForwarder() error
	StopPortForwarder()
	GetPortForwardLocalhost() string
}

type OperatorScanInfo interface {
	GetRequestPayload() *apis.Commands
	ValidatePayload(*apis.Commands) error
}

func (v *VulnerabilitiesScanInfo) ValidatePayload(commands *apis.Commands) error {
	return nil
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

func (c *ConfigScanInfo) ValidatePayload(commands *apis.Commands) error {
	if len(c.IncludedNamespaces) != 0 && len(c.ExcludedNamespaces) != 0 {
		return errors.New("invalid arguments: include-namespaces and exclude-namespaces can't pass together to the CLI")
	}
	return nil
}

func (c *ConfigScanInfo) GetRequestPayload() *apis.Commands {
	if len(c.Frameworks) == 0 {
		c.Frameworks = append(c.Frameworks, "all")
	}
	return &apis.Commands{
		Commands: []apis.Command{
			{
				CommandName: apis.TypeRunKubescape,
				Args: map[string]interface{}{
					KubescapeScanV1: utilsmetav1.PostScanRequest{
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
