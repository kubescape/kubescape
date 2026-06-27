package operator

import (
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

const (
	annotateSubCommand string = "annotate"
	revertSubCommand   string = "revert"
)

var operatorRemediateExamples = fmt.Sprintf(`
  # Preview (dry-run) annotating a workload as remediated — no changes are made
  %[1]s operator remediate annotate --kind Deployment --namespace payments --name api --reason "C-0016"

  # Apply the annotation (the only flag that performs a real cluster write)
  %[1]s operator remediate annotate --kind Deployment --namespace payments --name api --reason "C-0016" --confirm

  # Revert a previously applied annotation
  %[1]s operator remediate revert --kind Deployment --namespace payments --name api --confirm

`, cautils.ExecName())

// getOperatorRemediateCmd wires the `operator remediate <action>` subcommand.
// The action (annotate|revert) is a positional argument, matching the proposal's
// CLI surface; remediation reuses the existing operator-scan transport, so the
// command only assembles a RemediationInfo and hands it to the OperatorAdapter.
func getOperatorRemediateCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	remediationInfo := &cautils.RemediationInfo{}

	remediateCmd := &cobra.Command{
		Use:     "remediate <action>",
		Short:   "Act on scan findings via the Kubescape Operator (Phase 1: annotate, revert — dry-run by default)",
		Long:    ``,
		Example: operatorRemediateExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, cautils.RemediateCommand)
			if len(args) < 1 {
				return fmt.Errorf("for the operator remediate sub-command, you must pass an action (%s or %s). Refer to the examples above", annotateSubCommand, revertSubCommand)
			}
			if args[0] != annotateSubCommand && args[0] != revertSubCommand {
				return fmt.Errorf("for the operator remediate sub-command, only %s and %s are supported. Refer to the examples above", annotateSubCommand, revertSubCommand)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("for the operator remediate sub-command, you must pass an action. Refer to the examples above")
			}
			remediationInfo.Action = args[0]
			operatorInfo.OperatorScanInfo = remediationInfo

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
			if remediationInfo.IsDryRun() {
				logger.L().StopSuccess("Submitted remediation (dry-run) — no changes are applied. Check the 'KubescapeRemediation' event (kubectl get events -n <namespace>) or the operator logs for the plan; re-run with --confirm to apply.")
			} else {
				logger.L().StopSuccess("Submitted remediation (apply). Check the 'KubescapeRemediation' event (kubectl get events -n <namespace>) or the operator logs for the result.")
			}
			return nil
		},
	}

	remediateCmd.PersistentFlags().StringVar(&operatorInfo.Namespace, "namespace", "kubescape", "namespace of the Kubescape Operator")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Kind, "kind", "", "target workload kind: Deployment, StatefulSet, DaemonSet or Pod")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Namespace, "target-namespace", "", "namespace of the target workload")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Name, "name", "", "name of the target workload")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.Reason, "reason", "", "human-readable justification recorded in the audit trail")
	remediateCmd.PersistentFlags().StringVar(&remediationInfo.FindingRef, "finding-ref", "", "scan-result reference that justifies the action, e.g. workloadconfigurationscansummaries/payments/api")
	remediateCmd.PersistentFlags().BoolVar(&remediationInfo.DryRun, "dry-run", true, "preview the action without applying it (server-side validated); use --confirm to apply")
	remediateCmd.PersistentFlags().BoolVar(&remediationInfo.Confirm, "confirm", false, "perform the real cluster write (overrides --dry-run)")

	return remediateCmd
}
