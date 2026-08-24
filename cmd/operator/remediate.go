package operator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/spf13/cobra"
)

const (
	annotateSubCommand   string = "annotate"
	quarantineSubCommand string = "quarantine"
	revertSubCommand     string = "revert"
)

// remediateActions is the set of actions the CLI accepts, in help/error order.
var remediateActions = []string{annotateSubCommand, quarantineSubCommand, revertSubCommand}

func isSupportedRemediateAction(action string) bool {
	for _, a := range remediateActions {
		if a == action {
			return true
		}
	}
	return false
}

var operatorRemediateExamples = fmt.Sprintf(`
  # Preview (dry-run) annotating a workload as remediated — no changes are made
  %[1]s operator remediate annotate --kind Deployment --target-namespace payments --name api --reason "C-0016"

  # Apply the annotation (the only flag that performs a real cluster write)
  %[1]s operator remediate annotate --kind Deployment --target-namespace payments --name api --reason "C-0016" --confirm

  # Preview (dry-run) quarantining a workload — creates a deny-all NetworkPolicy isolating its pods
  %[1]s operator remediate quarantine --kind Deployment --target-namespace payments --name api --reason "C-0016"

  # Apply the quarantine
  %[1]s operator remediate quarantine --kind Deployment --target-namespace payments --name api --reason "C-0016" --confirm

  # Revert a previously applied action (removes the annotation and/or NetworkPolicy on the target)
  %[1]s operator remediate revert --kind Deployment --target-namespace payments --name api --confirm

  # Findings-driven: preview every workload failing a control at High or above.
  # Targets are resolved from scan results already stored in the cluster — no re-scan.
  %[1]s operator remediate quarantine --control C-0016 --min-severity High

  # Apply it once the previewed plan has been reviewed
  %[1]s operator remediate quarantine --control C-0016 --min-severity High --confirm

`, cautils.ExecName())

// getOperatorRemediateCmd wires the `operator remediate <action>` subcommand.
// The action is a positional argument, matching the proposal's CLI surface;
// remediation reuses the existing operator-scan transport, so the command only
// assembles a RemediationInfo and hands it to the OperatorAdapter. The target is
// either explicit (--kind/--name) or findings-driven (--control/--min-severity),
// the latter resolved in-cluster by the operator from stored scan results.
func getOperatorRemediateCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	remediationInfo := &cautils.RemediationInfo{}

	remediateCmd := &cobra.Command{
		Use:     "remediate <action>",
		Short:   "Act on scan findings via the Kubescape Operator (annotate, quarantine, revert — dry-run by default)",
		Long:    ``,
		Example: operatorRemediateExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, cautils.RemediateCommand)
			if len(args) != 1 {
				return fmt.Errorf("for the operator remediate sub-command, you must pass exactly one action (%s). Refer to the examples above", strings.Join(remediateActions, ", "))
			}
			if !isSupportedRemediateAction(args[0]) {
				return fmt.Errorf("for the operator remediate sub-command, only %s are supported. Refer to the examples above", strings.Join(remediateActions, ", "))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("for the operator remediate sub-command, you must pass exactly one action. Refer to the examples above")
			}
			remediationInfo.Action = args[0]
			operatorInfo.OperatorScanInfo = remediationInfo

			// Validate the input before touching the cluster so typos (bad action,
			// missing target) fail instantly, instead of after connecting and
			// locating the operator pod. OperatorScan validates again — harmless.
			if err := remediationInfo.ValidatePayload(nil); err != nil {
				return err
			}

			// annotate and quarantine write an audit trail; nudge (don't block) for a justification.
			if (remediationInfo.Action == annotateSubCommand || remediationInfo.Action == quarantineSubCommand) && remediationInfo.Reason == "" {
				logger.L().Warning(fmt.Sprintf("no --reason provided; %s records an audit trail, consider adding --reason to justify the action", remediationInfo.Action))
			}

			// A confirmed selector run resolves cluster-wide and can write to many
			// workloads at once; say so before it happens, since the caller named
			// no single object and cannot see the resolved set from here.
			if remediationInfo.HasSelector() && !remediationInfo.IsDryRun() {
				logger.L().Warning(fmt.Sprintf("applying %q to every workload matching the selector, across all namespaces", remediationInfo.Action))
			}

			operatorAdapter, err := core.NewOperatorAdapter(operatorInfo.OperatorScanInfo, operatorInfo.Namespace)
			if err != nil {
				return err
			}

			verb := "Previewing"
			if !remediationInfo.IsDryRun() {
				verb = "Applying"
			}
			logger.L().Start(fmt.Sprintf("%s remediation %q via Kubescape Operator", verb, remediationInfo.Action))
			if _, err := operatorAdapter.OperatorScan(); err != nil {
				logger.L().StopError("Failed to submit remediation to Kubescape Operator", helpers.Error(err))
				return err
			}
			// The operator processes the command asynchronously (the triggerAction
			// endpoint acknowledges receipt and queues the work), so the outcome is
			// not returned here. It is emitted as a "KubescapeRemediation" Kubernetes
			// Event on the target namespace and recorded in the operator logs.
			// A selector resolves targets across namespaces, so its audit Events are
			// not confined to the one namespace an explicit target would name.
			eventsScope := fmt.Sprintf("-n %s", remediationInfo.Namespace)
			if remediationInfo.HasSelector() {
				eventsScope = "--all-namespaces"
			}
			eventsHint := fmt.Sprintf("kubectl get events %s --field-selector reason=KubescapeRemediation", eventsScope)
			if remediationInfo.IsDryRun() {
				logger.L().StopSuccess(fmt.Sprintf("Submitted remediation (dry-run) — no changes are applied. Check the plan via '%s' or the operator logs; re-run with --confirm to apply.", eventsHint))
			} else {
				logger.L().StopSuccess(fmt.Sprintf("Submitted remediation (apply). Check the result via '%s' or the operator logs.", eventsHint))
			}
			return nil
		},
	}

	remediateCmd.PersistentFlags().StringVar(&operatorInfo.Namespace, "namespace", "kubescape", "namespace of the Kubescape Operator")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Kind, "kind", "", "target workload kind: Deployment, StatefulSet, DaemonSet or Pod")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Namespace, "target-namespace", "", "namespace of the target workload")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Name, "name", "", "name of the target workload")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Control, "control", "", "act on workloads failing this control, e.g. C-0016 (resolved from stored scan results; mutually exclusive with --kind/--name)")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.MinSeverity, "min-severity", "", "act on workloads with a failing finding at or above this severity: Critical, High, Medium, Low or Unknown (mutually exclusive with --kind/--name)")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Reason, "reason", "", "human-readable justification recorded in the audit trail")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.FindingRef, "finding-ref", "", "scan-result reference that justifies the action, e.g. workloadconfigurationscansummaries/payments/api")
	remediateCmd.PersistentFlags().BoolVar(&remediationInfo.Confirm, "confirm", false, "perform the real cluster write; without it the action is a dry-run preview")

	return remediateCmd
}
