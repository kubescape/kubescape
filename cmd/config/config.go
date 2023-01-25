package config

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

var (
	configExample = fmt.Sprintf(`
  # View cached configurations 
  %[1]s config view

  # Delete cached configurations
  %[1]s config delete

  # Set cached configurations
  %[1]s config set --help
`, cautils.ExecName())
	setConfigExample = fmt.Sprintf(`
  # Set account id
  %[1]s config set accountID <account id>

  # Set client id
  %[1]s config set clientID <client id> 

  # Set access key
  %[1]s config set secretKey <access key>

  # Set cloudAPIURL
  %[1]s config set cloudAPIURL <cloud API URL>
`, cautils.ExecName())
)

func GetConfigCmd(ks meta.IKubescape) *cobra.Command {

	// configCmd represents the config command
	configCmd := &cobra.Command{
		Use:     "config",
		Short:   "Handle cached configurations",
		Example: configExample,
	}

	configCmd.AddCommand(getDeleteCmd(ks))
	configCmd.AddCommand(getSetCmd(ks))
	configCmd.AddCommand(getViewCmd(ks))

	return configCmd
}
