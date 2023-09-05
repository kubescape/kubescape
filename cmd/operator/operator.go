package operator

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/spf13/cobra"
)

var operatorExamples = fmt.Sprintf(`
  Operator command is for control the cluster from the kubescape CLI 
  
  # Run a configuration scan
  %[1]s operator scan config

  # Run a vulnerabilities scan
  %[1]s operator scan vulnerabilities

`, cautils.ExecName())

func GetOperatorCmd(ks meta.IKubescape) *cobra.Command {
	var operatorInfo cautils.OperatorInfo

	operatorCmd := &cobra.Command{
		Use:     "operator",
		Short:   "Operator - use for communicate with the kubescape in cluster components",
		Long:    ``,
		Example: operatorExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "operator")
			if len(args) < 1 {
				return errors.New("for operator sub command, you must pass at least 1 more sub commands, see above examples")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	operatorCmd.AddCommand(getOperatorScanCmd(ks, operatorInfo))

	return operatorCmd
}
