package operator

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/core"
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
			operatorInfo.OperatorServicesStatus.ScanVulnerabilities = true
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "vulnerabilities")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			operatorAdapter, err := core.NewOperatorAdapter()
			if err != nil {
				return err
			}
			resp, err := operatorAdapter.OperatorScan(operatorInfo)
			if err != nil {
				fmt.Printf("%s", resp)
			}
			return err
		},
	}

	configCmd.PersistentFlags().StringSliceVar(&operatorInfo.VulnerabilitiesScanInfo.IncludeNamespaces, "include-namespaces", nil, "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")

	return configCmd
}
