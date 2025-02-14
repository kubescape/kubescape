package prerequisites

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/kubescape/sizing-checker/pkg/checks/pvcheck"
	"github.com/kubescape/sizing-checker/pkg/checks/sizing"
	"github.com/kubescape/sizing-checker/pkg/common"
	"github.com/spf13/cobra"
)

func GetPreReqCmd(ks meta.IKubescape) *cobra.Command {
	var activeChecks bool

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

			// Conditionally run resource-deploying checks
			var pvResult *pvcheck.PVCheckResult
			if activeChecks {
				logger.L().Start("Running active checks")
				pvResult = pvcheck.RunPVProvisioningCheck(ks.Context(), clientSet, clusterData)
				logger.L().StopSuccess("Active checks complete")
			} else {
				// If not running active checks, fill with a "Skipped" result
				pvResult = &pvcheck.PVCheckResult{
					PassedCount:   0,
					FailedCount:   0,
					TotalNodes:    len(clusterData.Nodes),
					ResultMessage: "Skipped (use --active-checks to run)",
				}
			}

			// 3) Build and export the final ReportData
			finalReport := common.BuildReportData(clusterData, sizingResult)
			finalReport.PVProvisioningMessage = pvResult.ResultMessage

			common.GenerateOutput(finalReport, inCluster)
		},
	}

	preReqCmd.PersistentFlags().BoolVarP(&activeChecks, "active-checks", "", false, "If set, run checks that require resource deployment on the cluster.")

	return preReqCmd
}
