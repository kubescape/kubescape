package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/spf13/cobra"
)

var localSetCmd = &cobra.Command{
	Use:        "set <key>=<value>",
	Short:      "Set configuration locally",
	Long:       ``,
	Deprecated: "use the 'set' command instead",
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

		if err := cautils.SetKeyValueInConfigJson(key, data); err != nil {
			return err
		}
		fmt.Println("Value added successfully.")
		return nil
	},
}

func init() {
	localCmd.AddCommand(localSetCmd)
}
