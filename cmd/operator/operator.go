package operator

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

const (
	scanSubCommand      string = "scan"
	remediateSubCommand string = "remediate"
)

var operatorExamples = fmt.Sprintf(`

  # Trigger a configuration scan
  %[1]s operator scan configurations

  # Trigger a vulnerabilities scan
  %[1]s operator scan vulnerabilities

  # Preview a post-scan remediation (dry-run by default)
  %[1]s operator remediate annotate --kind Deployment --target-namespace payments --name api --reason "C-0016"

`, cautils.ExecName())

func GetOperatorCmd(ks meta.IKubescape) *cobra.Command {
	var operatorInfo cautils.OperatorInfo

	operatorCmd := &cobra.Command{
		Use:     "operator",
		Short:   "The operator is used to communicate with the Kubescape Operator within the cluster components.",
		Long:    ``,
		Example: operatorExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "operator")
			if len(args) < 2 {
				return errors.New("for the operator sub-command, you need to provide at least one additional sub-command. Refer to the examples above")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("for the operator sub-command, you need to provide at least one additional sub-command. Refer to the examples above")
			}
			if args[0] != scanSubCommand && args[0] != remediateSubCommand {
				return fmt.Errorf("for the operator sub-command, only %s and %s are supported. Refer to the examples above", scanSubCommand, remediateSubCommand)
			}
			return nil
		},
	}

	operatorCmd.AddCommand(getOperatorScanCmd(ks, operatorInfo))
	operatorCmd.AddCommand(getOperatorRemediateCmd(ks, operatorInfo))

	return operatorCmd
}
