package cmd

import (
	"fmt"
	"os"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	reporterv1 "github.com/armosec/kubescape/resultshandling/reporter/v1"
	"github.com/armosec/rbac-utils/rbacscanner"
	"github.com/spf13/cobra"
)

// rabcCmd represents the RBAC command
var rabcCmd = &cobra.Command{
	Use:   "rbac \nExample:\n$ kubescape submit rbac",
	Short: "Submit cluster's Role-Based Access Control(RBAC)",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {

		k8s := k8sinterface.NewKubernetesApi()

		// get config
		clusterConfig, err := getSubmittedClusterConfig(k8s)
		if err != nil {
			return err
		}

		// list RBAC
		rbacObjects := cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, clusterConfig.GetAccountID(), clusterConfig.GetClusterName()))

		// submit resources
		r := reporterv1.NewReportEventReceiver(clusterConfig.GetConfigObj())

		submitInterfaces := cliinterfaces.SubmitInterfaces{
			ClusterConfig: clusterConfig,
			SubmitObjects: rbacObjects,
			Reporter:      r,
		}

		if err := clihandler.Submit(submitInterfaces); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	submitCmd.AddCommand(rabcCmd)
}
