package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set <key>=<value>",
	Short: "Set configuration in cluster",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 1 {
			return fmt.Errorf("requires  one argument: <key>=<value>")
		}
		keyValue := strings.Split(args[0], "=")
		if len(keyValue) != 2 {
			return fmt.Errorf("requires  one argument: <key>=<value>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		keyValue := strings.Split(args[0], "=")
		key := keyValue[0]
		data := keyValue[1]

		k8s := k8sinterface.NewKubernetesApi()
		clusterConfig := cautils.NewClusterConfig(k8s, getter.NewArmoAPI())
		if err := clusterConfig.SetKeyValueInConfigmap(key, data); err != nil {
			return err
		}
		fmt.Println("Value added successfully.")
		return nil
	},
}

func init() {
	clusterCmd.AddCommand(setCmd)
}
