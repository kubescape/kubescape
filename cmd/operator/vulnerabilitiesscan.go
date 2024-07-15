package operator

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

var operatorScanVulnerabilitiesExamples = fmt.Sprintf(`

  # Trigger a vulnerabilities scan
  %[1]s operator scan vulnerabilities

`, cautils.ExecName())

func getOperatorScanVulnerabilitiesCmd(ks meta.IKubescape, operatorInfo cautils.OperatorInfo) *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "vulnerabilities",
		Short:   "Vulnerabilities use for scan your cluster vulnerabilities using Kubescape operator in the in cluster components",
		Long:    ``,
		Example: operatorScanVulnerabilitiesExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			operatorInfo.Subcommands = append(operatorInfo.Subcommands, "vulnerabilities")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			operatorAdapter, err := core.NewOperatorAdapter(operatorInfo.OperatorScanInfo, operatorInfo.Namespace)
			if err != nil {
				return err
			}
			logger.L().Start("Triggering the Kubescape Operator for vulnerability scanning")
			_, err = operatorAdapter.OperatorScan()
			if err != nil {
				logger.L().StopError("Failed to trigger the Kubescape Operator for vulnerability scanning", helpers.Error(err))
				return err
			}
			logger.L().StopSuccess("Triggered Kubescape Operator for vulnerability scanning. View the scanning results once they are ready using the following command: \"kubectl get vulnerabilitysummaries\"")
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
