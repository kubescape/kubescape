package cmd

import (
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var submitInfo cliobjects.Submit

var submitCmd = &cobra.Command{
	Use:   "submit <command>",
	Short: "Submit an object to the Kubescape SaaS version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	rootCmd.AddCommand(submitCmd)
}

func getSubmittedClusterConfig(k8s *k8sinterface.KubernetesApi) (*cautils.ClusterConfig, error) {
	clusterConfig := cautils.NewClusterConfig(k8s, getter.GetArmoAPIConnector(), submitInfo.Account, scanInfo.KubeContext) // TODO - support none cluster env submit
	if clusterConfig.GetAccountID() != "" {
		if err := clusterConfig.SetTenant(); err != nil {
			return clusterConfig, err
		}
	}

	return clusterConfig, nil
}
