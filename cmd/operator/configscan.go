package operator

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

func getOperatorScanConfigCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "config",
		Short:   "config - use for scan your cluster configuration using the in cluster components",
		Long:    ``,
		Example: operatorExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "config")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	configCmd.PersistentFlags().StringVar(&operatorInfo.ConfigScanInfo.IncludeNamespaces, "include-namespaces", "", "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")
	configCmd.PersistentFlags().StringVarP(&operatorInfo.ConfigScanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. e.g: --exclude-namespaces ns-a,ns-b. Notice, when running with `exclude-namespace` kubescape does not scan cluster-scoped objects.")
	configCmd.PersistentFlags().BoolVarP(&operatorInfo.ConfigScanInfo.Submit, "submit", "", false, "Submit the scan results to Kubescape SaaS where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	configCmd.PersistentFlags().StringSliceVar(&operatorInfo.Frameworks, "frameworks", nil, "Load frameworks for config scan")
	hostF := configCmd.PersistentFlags().VarPF(&operatorInfo.HostSensorEnabled, "enable-host-scan", "", "Deploy Kubescape host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls. Yaml file: https://github.com/kubescape/kubescape/blob/master/core/pkg/hostsensorutils/hostsensor.yaml")
	hostF.NoOptDefVal = "true"
	hostF.DefValue = "false, for no TTY in stdin"

	return configCmd
}
