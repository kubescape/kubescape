package cautils

import (
	"errors"
	"fmt"
	"strings"

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
	RemediateCommand           OperatorSubCommand = "remediate"
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
				Args: map[string]any{
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

// remediationTargetKinds are the workload kinds the Phase-1 operator can act on
// (see operator mainhandler/remediators/annotate.go). All are namespaced.
var remediationTargetKinds = map[string]bool{
	"deployment":  true,
	"statefulset": true,
	"daemonset":   true,
	"pod":         true,
}

// RemediationInfo carries a single `kubescape operator remediate <action>`
// invocation. It implements OperatorScanInfo so it reuses the existing
// OperatorAdapter transport (POST apis.Commands to v1/triggerAction) — a
// remediation is a new verb on that pipeline, not a new endpoint.
//
// Phase 1 supports the lowest-blast-radius actions only: `annotate` and its
// `revert`, on an explicit target. Findings-driven targeting (--control /
// --min-severity) and the quarantine/cordon actions arrive in later phases.
type RemediationInfo struct {
	// Action is the operation to perform: "annotate" or "revert".
	Action string
	// Target (explicit, Phase 1).
	Kind      string
	Namespace string
	Name      string
	// Audit metadata.
	Reason     string
	FindingRef string
	// Confirm (the --confirm flag) is the only way to perform a real cluster
	// write; absent it, the action is a dry-run. See IsDryRun.
	Confirm bool
}

// IsDryRun reports whether the action should be sent as a plan-only dry-run.
// It is the inverse of --confirm, so an action is a dry-run unless the caller
// explicitly confirms — a forgotten flag can never perform a real write, and
// no caller can apply without setting Confirm.
func (r *RemediationInfo) IsDryRun() bool {
	return !r.Confirm
}

func (r *RemediationInfo) ValidatePayload(*apis.Commands) error {
	switch apis.OperatorActionType(r.Action) {
	case apis.OperatorActionAnnotate, apis.OperatorActionRevert:
		// supported in Phase 1
	case apis.OperatorActionQuarantine, apis.OperatorActionCordon:
		return fmt.Errorf("remediation action %q is not supported yet (planned for a later phase); supported: annotate, revert", r.Action)
	default:
		return fmt.Errorf("unknown remediation action %q (supported: annotate, revert)", r.Action)
	}

	if r.Kind == "" || r.Name == "" {
		return errors.New("remediation target requires --kind and --name")
	}
	if !remediationTargetKinds[strings.ToLower(r.Kind)] {
		return fmt.Errorf("unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", r.Kind)
	}
	if r.Namespace == "" {
		return fmt.Errorf("target kind %q requires --target-namespace", r.Kind)
	}
	return nil
}

func (r *RemediationInfo) GetRequestPayload() *apis.Commands {
	dryRun := r.IsDryRun()
	args := apis.OperatorActionArgs{
		Action: apis.OperatorActionType(r.Action),
		Target: &apis.OperatorActionTarget{
			Kind:      r.Kind,
			Namespace: r.Namespace,
			Name:      r.Name,
		},
		Reason:     r.Reason,
		FindingRef: r.FindingRef,
		DryRun:     &dryRun,
	}
	// ToArgs marshals a plain struct, so it cannot fail in practice; an empty
	// Args map would be rejected by the operator with a clear error anyway.
	actionArgs, _ := args.ToArgs()

	return &apis.Commands{
		Commands: []apis.Command{
			{
				CommandName: apis.TypeOperatorAction,
				Args:        actionArgs,
			},
		},
	}
}
