package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/spf13/cobra"
)

// localGetCmd represents the localGet command
var localGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get configuration locally",
	Long:  ``,
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
		clusterConfig := cautils.NewClusterConfig(k8s, getter.NewArmoAPI())
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
	localCmd.AddCommand(localGetCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// localGetCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// localGetCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
