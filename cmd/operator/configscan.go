package operator

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

var operatorScanConfigExamples = fmt.Sprintf(`
  
  # Run a configuration scan
  %[1]s operator scan configurations

`, cautils.ExecName())

func getOperatorScanConfigCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "configurations",
		Short:   "Trigger configuration scanning from the Kubescape Operator microservice",
		Long:    ``,
		Example: operatorScanConfigExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "config")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			operatorAdapter, err := core.NewOperatorAdapter(operatorInfo.OperatorScanInfo, operatorInfo.Namespace)
			if err != nil {
				return err
			}
			logger.L().Start("Kubescape Operator Triggering for configuration scanning")
			_, err = operatorAdapter.OperatorScan()
			if err != nil {
				logger.L().StopError("Failed to triggering Kubescape Operator for configuration scanning", helpers.Error(err))
				return err
			}
			logger.L().StopSuccess("Triggered Kubescape Operator for configuration scanning")
			return nil
		},
	}

	configScanInfo := &cautils.ConfigScanInfo{}
	operatorInfo.OperatorScanInfo = configScanInfo

	configCmd.PersistentFlags().StringSliceVar(&configScanInfo.IncludedNamespaces, "include-namespaces", nil, "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	configCmd.PersistentFlags().StringSliceVar(&configScanInfo.ExcludedNamespaces, "exclude-namespaces", nil, "Namespaces to exclude from scanning. e.g: --exclude-namespaces ns-a,ns-b. Notice, when running with `exclude-namespace` kubescape does not scan cluster-scoped objects.")
	configCmd.PersistentFlags().StringSliceVar(&configScanInfo.Frameworks, "frameworks", nil, "Load frameworks for configuration scanning")
	configCmd.PersistentFlags().BoolVarP(&configScanInfo.HostScanner, "enable-host-scan", "", false, "Deploy Kubescape host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls. Yaml file: https://github.com/kubescape/kubescape/blob/master/core/pkg/hostsensorutils/hostsensor.yaml")

	return configCmd
}
