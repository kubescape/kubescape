package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/spf13/cobra"
)

var localGetCmd = &cobra.Command{
	Use:        "get <key>",
	Short:      "Get configuration locally",
	Long:       ``,
	Deprecated: "use the 'view' command instead",
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

		val, err := cautils.GetValueFromConfigJson(key)
		if err != nil {
			if err.Error() == "value does not exist." {
				return fmt.Errorf("failed to get value from: %s, reason: %s", cautils.ConfigFileFullPath(), err.Error())
			}
			return err
		}
		fmt.Println(key + "=" + val)
		return nil
	},
}

func init() {
	localCmd.AddCommand(localGetCmd)
}
