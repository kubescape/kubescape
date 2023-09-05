package operator

import (
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

func getOperatorScanVulnerabilitiesCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "vulnerabilities",
		Short:   "Vulnerabilities - use for scan your cluster vulnerabilities using the in cluster components",
		Long:    ``,
		Example: operatorExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "vulnerabilities")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	configCmd.PersistentFlags().StringSliceVar(&operatorInfo.VulnerabilitiesScanInfo.IncludeNamespaces, "include-namespaces", nil, "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")

	return configCmd
}
