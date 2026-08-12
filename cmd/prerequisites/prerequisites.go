package prerequisites

import (
	"context"
	"fmt"

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

var (
	buildKubeClient    = common.BuildKubeClient
	collectClusterData = common.CollectClusterData
)

func GetPreReqCmd(ks meta.IKubescape) *cobra.Command {
	var kubeconfigPath *string

	// preReqCmd represents the prerequisites command
	preReqCmd := &cobra.Command{
		Use:   "prerequisites",
		Short: "Check prerequisites for installing Kubescape Operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPrerequisites(ks.Context(), *kubeconfigPath)
		},
	}

	kubeconfigPath = preReqCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file. If not set, in-cluster config is used or $HOME/.kube/config if outside a cluster.")

	return preReqCmd
}

// runPrerequisites collects cluster data and runs operator prerequisite checks.
// Collection failures must abort before checks/report generation: partial data
// previously produced false-negative PV results and unsafe Helm recommendations
// while still exiting 0.
func runPrerequisites(ctx context.Context, kubeconfigPath string) error {
	clientSet, inCluster := buildKubeClient(kubeconfigPath)
	if clientSet == nil {
		return fmt.Errorf("could not create kube client")
	}

	clusterData, err := collectClusterData(ctx, clientSet)
	if err != nil {
		logger.L().Error("Failed to collect cluster data", helpers.Error(err))
		return fmt.Errorf("failed to collect cluster data: %w", err)
	}

	sizingResult := sizing.RunSizingChecker(clusterData)
	pvResult := pvcheck.RunPVProvisioningCheck(ctx, clientSet, clusterData, inCluster)
	connectivityResult := connectivitycheck.RunConnectivityChecks(ctx, clientSet, clusterData, inCluster)
	ebpfResult := ebpfcheck.RunEbpfCheck(ctx, clientSet, clusterData, inCluster)

	finalReport := common.BuildReportData(clusterData, sizingResult, pvResult, connectivityResult, ebpfResult)
	finalReport.InCluster = inCluster

	common.GenerateOutput(finalReport, inCluster)
	return nil
}
