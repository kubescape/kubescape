package operator

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

const (
	vulnerabilitiesSubCommand string = "vulnerabilities"
	configurationsSubCommand  string = "configurations"
)

func getOperatorScanCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	operatorCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan your cluster using the Kubescape-operator within the cluster components",
		Long:    ``,
		Example: operatorExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "scan")
			if len(args) < 1 {
				return errors.New("for operator scan sub command, you must pass at least 1 more sub commands, see above examples")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("for operator scan sub command, you must pass at least 1 more sub commands, see above examples")
			}
			if (args[0] != vulnerabilitiesSubCommand) && (args[0] != configurationsSubCommand) {
				return errors.New(fmt.Sprintf("For the operator sub-command, only %s and %s are supported. Refer to the examples above.", vulnerabilitiesSubCommand, configurationsSubCommand))
			}
			return nil
		},
	}

	operatorCmd.PersistentFlags().StringVar(&operatorInfo.Namespace, "namespace", "kubescape", "namespace of the Kubescape Operator")
	operatorCmd.AddCommand(getOperatorScanConfigCmd(ks, operatorInfo))
	operatorCmd.AddCommand(getOperatorScanVulnerabilitiesCmd(ks, operatorInfo))

	return operatorCmd
}
