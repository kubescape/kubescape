package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:       "get <key>",
	Short:     "Get configuration in cluster",
	Long:      ``,
	ValidArgs: supportedFrameworks,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 1 {
			return fmt.Errorf("requires  one argument")
		}

		keyValue := strings.Split(args[0], "=")
		if len(keyValue) != 1 {
			return fmt.Errorf("requires  one argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		keyValue := strings.Split(args[0], "=")
		key := keyValue[0]

		k8s := k8sinterface.NewKubernetesApi()
		clusterConfig := cautils.NewClusterConfig(k8s, getter.GetArmoAPIConnector())
		val, err := clusterConfig.GetValueByKeyFromConfigMap(key)
		if err != nil {
			if err.Error() == "value does not exist." {
				fmt.Printf("Could net get value from configmap, reason: %s\n", err)
				return nil
			}
			return err
		}
		fmt.Println(key + "=" + val)
		return nil
	},
}

func init() {
	clusterCmd.AddCommand(getCmd)
}
