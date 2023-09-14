package operator

import (
	"fmt"

	"github.com/kubescape/k8s-interface/k8sinterface"
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
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "vulnerabilities")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			operatorAdapter, err := core.NewOperatorAdapter(operatorInfo.OperatorScanInfo)
			if err != nil {
				return err
			}
			resp, err := operatorAdapter.OperatorScan()
			if err != nil {
				fmt.Printf("%s", resp)
			}
			return err
		},
	}

	vulnerabilitiesScanInfo := &cautils.VulnerabilitiesScanInfo{
		ClusterName: k8sinterface.GetContextName(),
	}
	operatorInfo.OperatorScanInfo = vulnerabilitiesScanInfo

	configCmd.PersistentFlags().StringSliceVar(&vulnerabilitiesScanInfo.IncludeNamespaces, "include-namespaces", nil, "scan specific namespaces. e.g: --include-namespaces ns-a,ns-b")

	return configCmd
}
