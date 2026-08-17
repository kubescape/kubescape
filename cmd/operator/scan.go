package operator

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

const (
	vulnerabilitiesSubCommand string = "vulnerabilities"
	configurationsSubCommand  string = "configurations"
)

var operatorScanExamples = fmt.Sprintf(`

  # Trigger a configuration scan
  %[1]s operator scan configurations

  # Trigger a vulnerabilities scan
  %[1]s operator scan vulnerabilities

`, cautils.ExecName())

// newOperatorAdapter is a seam over core.NewOperatorAdapter: the "configurations"
// and "vulnerabilities" child commands call it to reach the cluster. Tests
// substitute it to assert on the (scanInfo, namespace) a child actually sends
// without connecting to a real cluster.
var newOperatorAdapter = core.NewOperatorAdapter

func getOperatorScanCmd(ks meta.IKubescape, operatorInfo *cautils.OperatorInfo) *cobra.Command {
	operatorCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan your cluster using the Kubescape-operator within the cluster components",
		Long:    ``,
		Example: operatorScanExamples,
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
				return fmt.Errorf("for the operator sub-command, only %s and %s are supported. Refer to the examples above", vulnerabilitiesSubCommand, configurationsSubCommand)
			}
			return nil
		},
	}

	operatorCmd.PersistentFlags().StringVar(&operatorInfo.Namespace, "namespace", "kubescape", "namespace of the Kubescape Operator")
	operatorCmd.AddCommand(getOperatorScanConfigCmd(ks, operatorInfo))
	operatorCmd.AddCommand(getOperatorScanVulnerabilitiesCmd(ks, operatorInfo))

	return operatorCmd
}
