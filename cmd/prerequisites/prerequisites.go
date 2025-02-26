package prerequisites

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/kubescape/sizing-checker/pkg/checks/connectivitycheck"
	"github.com/kubescape/sizing-checker/pkg/checks/ebpfcheck"
	"github.com/kubescape/sizing-checker/pkg/checks/pvcheck"
	"github.com/kubescape/sizing-checker/pkg/checks/sizing"
	"github.com/kubescape/sizing-checker/pkg/common"
	"github.com/spf13/cobra"
)

func GetPreReqCmd(ks meta.IKubescape) *cobra.Command {
	// preReqCmd represents the prerequisites command
	preReqCmd := &cobra.Command{
		Use:   "prerequisites",
		Short: "Check prerequisites for installing Kubescape Operator",
		Run: func(cmd *cobra.Command, args []string) {
			clientSet, inCluster := common.BuildKubeClient()
			if clientSet == nil {
				logger.L().Fatal("Could not create kube client. Exiting.")
			}

			// 1) Collect cluster data
			clusterData, err := common.CollectClusterData(ks.Context(), clientSet)
			if err != nil {
				logger.L().Error("Failed to collect cluster data", helpers.Error(err))
			}

			// 2) Run checks
			sizingResult := sizing.RunSizingChecker(clusterData)
			pvResult := pvcheck.RunPVProvisioningCheck(ks.Context(), clientSet, clusterData, inCluster)
			connectivityResult := connectivitycheck.RunConnectivityChecks(ks.Context(), clientSet, clusterData, inCluster)
			ebpfResult := ebpfcheck.RunEbpfCheck(ks.Context(), clientSet, clusterData, inCluster)

			// 3) Build and export the final ReportData
			finalReport := common.BuildReportData(clusterData, sizingResult, pvResult, connectivityResult, ebpfResult)
			finalReport.InCluster = inCluster

			common.GenerateOutput(finalReport, inCluster)
		},
	}
	return preReqCmd
}
