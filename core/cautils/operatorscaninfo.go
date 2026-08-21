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

// remediationTargetKinds are the workload kinds the operator can act on
// (see operator mainhandler/remediators/annotate.go). All are namespaced.
var remediationTargetKinds = map[string]bool{
	"deployment":  true,
	"statefulset": true,
	"daemonset":   true,
	"pod":         true,
}

// remediationSeverities are the --min-severity values the operator's
// findings-driven targeting understands. It deliberately mirrors the operator's
// severityRank (mainhandler/findings.go) rather than
// reporthandlingapis.GetSupportedSeverities, which omits "Unknown": rejecting
// here a value the operator accepts would be a gratuitous divergence between
// the two ends of one contract.
var remediationSeverities = []string{"Critical", "High", "Medium", "Low", "Unknown"}

func isSupportedRemediationSeverity(severity string) bool {
	for _, s := range remediationSeverities {
		if strings.EqualFold(strings.TrimSpace(severity), s) {
			return true
		}
	}
	return false
}

// RemediationInfo carries a single `kubescape operator remediate <action>`
// invocation. It implements OperatorScanInfo so it reuses the existing
// OperatorAdapter transport (POST apis.Commands to v1/triggerAction) — a
// remediation is a new verb on that pipeline, not a new endpoint.
//
// Supported actions: `annotate`, `quarantine` and `revert`; the `cordon` action
// arrives in a later phase. A target is given either explicitly (--kind/--name)
// or as a findings-driven selector (--control/--min-severity) that the operator
// resolves against the scan results already stored in the cluster.
type RemediationInfo struct {
	// Action is the operation to perform: "annotate", "quarantine" or "revert".
	Action string
	// Target (explicit).
	Kind      string
	Namespace string
	Name      string
	// Selector (findings-driven): the operator resolves these against the stored
	// configuration-scan summaries, so no re-scan is performed. Mutually
	// exclusive with the explicit target above.
	Control     string
	MinSeverity string
	// Audit metadata.
	Reason     string
	FindingRef string
	// Confirm (the --confirm flag) is the only way to perform a real cluster
	// write; absent it, the action is a dry-run. See IsDryRun.
	Confirm bool
}

// HasSelector reports whether findings-driven targeting was requested.
func (r *RemediationInfo) HasSelector() bool {
	return r.Control != "" || r.MinSeverity != ""
}

// HasExplicitTarget reports whether a single concrete object was named.
func (r *RemediationInfo) HasExplicitTarget() bool {
	return r.Kind != "" || r.Name != ""
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
	case apis.OperatorActionAnnotate, apis.OperatorActionQuarantine, apis.OperatorActionRevert:
		// supported: annotate + revert (Phase 1), quarantine (Phase 2)
	case apis.OperatorActionCordon:
		return fmt.Errorf("remediation action %q is not supported yet (planned for a later phase); supported: annotate, quarantine, revert", r.Action)
	default:
		return fmt.Errorf("unknown remediation action %q (supported: annotate, quarantine, revert)", r.Action)
	}

	// A remediation is aimed either at one named object or at whatever the
	// stored findings resolve to — never both, since the two would describe
	// different target sets and there is no sensible way to reconcile them.
	switch {
	case r.HasExplicitTarget() && r.HasSelector():
		return errors.New("--kind/--name and --control/--min-severity are mutually exclusive: pass either an explicit target or a findings selector")
	case r.HasSelector():
		return r.validateSelector()
	case r.HasExplicitTarget():
		return r.validateExplicitTarget()
	default:
		return errors.New("remediation requires a target: --kind and --name for one workload, or --control and/or --min-severity to select workloads from stored scan findings")
	}
}

// validateSelector checks findings-driven targeting. The target set itself is
// resolved in-cluster by the operator against the stored scan results, so the
// CLI validates only what it can know locally.
func (r *RemediationInfo) validateSelector() error {
	if r.MinSeverity != "" && !isSupportedRemediationSeverity(r.MinSeverity) {
		return fmt.Errorf("unsupported --min-severity %q (supported: %s)", r.MinSeverity, strings.Join(remediationSeverities, ", "))
	}
	// The operator resolves a selector across every namespace and has no
	// namespace filter yet (resolveSelectorTargets in mainhandler/findings.go
	// ignores selector.namespace), so honouring --target-namespace here would
	// silently widen the blast radius from one namespace to the whole cluster.
	// Reject it rather than mislead the caller into thinking they scoped it.
	if r.Namespace != "" {
		return errors.New("--target-namespace cannot be combined with --control/--min-severity: the operator resolves a findings selector cluster-wide and cannot scope it to a namespace yet")
	}
	return nil
}

// validateExplicitTarget checks a single named object.
func (r *RemediationInfo) validateExplicitTarget() error {
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
		Action:     apis.OperatorActionType(r.Action),
		Reason:     r.Reason,
		FindingRef: r.FindingRef,
		DryRun:     &dryRun,
	}
	// ValidatePayload guarantees exactly one of the two is set. Emit them
	// independently anyway so an unvalidated call cannot ship an empty Target,
	// which the operator would take as a request to act on a nameless object.
	if r.HasExplicitTarget() {
		args.Target = &apis.OperatorActionTarget{
			Kind:      r.Kind,
			Namespace: r.Namespace,
			Name:      r.Name,
		}
	}
	if r.HasSelector() {
		args.Selector = &apis.OperatorActionSelector{
			Control:     r.Control,
			MinSeverity: r.MinSeverity,
		}
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
