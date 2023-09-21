package operator

import (
	"errors"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

func getOperatorScanCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	operatorCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan use for scan your cluster using Kubescape operator in the in-cluster components",
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
			return nil
		},
	}

	operatorCmd.AddCommand(getOperatorScanConfigCmd(ks, operatorInfo))
	operatorCmd.AddCommand(getOperatorScanVulnerabilitiesCmd(ks, operatorInfo))

	return operatorCmd
}
